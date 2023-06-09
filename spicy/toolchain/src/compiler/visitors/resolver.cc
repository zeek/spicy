// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/unresolved-id.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/plugin.h>
#include <hilti/global.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/unresolved-field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream Resolver("resolver");
inline const hilti::logging::DebugStream Operator("operator");
} // namespace spicy::logging::debug

namespace {
// Turns an unresolved field into a resolved field.
template<typename T>
auto resolveField(const type::unit::item::UnresolvedField& u, T t) {
    auto field = type::unit::item::Field(u.fieldID(), std::move(t), u.engine(), u.isSkip(), u.arguments().copy(),
                                         u.repeatCount(), u.sinks().copy(), u.attributes(), u.condition(),
                                         u.hooks().copy(), u.meta());

    assert(u.index());
    field.setIndex(*u.index());
    return field;
}

// Helper type to select which type of a unit field we are interested in.
enum class FieldType {
    DDType,    // type for $$
    ItemType,  // final type of the field's value
    ParseType, // type that the field is being parsed at
};

// Visitor determining a unit field type.
struct FieldTypeVisitor : public hilti::visitor::PreOrder<Type, FieldTypeVisitor> {
    explicit FieldTypeVisitor(FieldType ft) : ft(ft) {}

    FieldType ft;

    result_t operator()(const type::Bitfield& t) {
        switch ( ft ) {
            case FieldType::DDType:
            case FieldType::ItemType: return t.type();

            case FieldType::ParseType: return t;
        };

        hilti::util::cannot_be_reached();
    }

    result_t operator()(const hilti::type::RegExp& /* t */) { return hilti::type::Bytes(); }
};

// Helper function to compute one of several kinds of a field's types.
std::optional<Type> _fieldType(const type::unit::item::Field& f, const Type& type, FieldType ft, bool is_container,
                               const Meta& meta) {
    Type nt;
    if ( auto e = FieldTypeVisitor(ft).dispatch(type) )
        nt = std::move(*e);
    else
        nt = type;

    if ( ! type::isResolved(nt) )
        return {};

    if ( is_container )
        return type::Vector(nt, meta);
    else
        return nt;
}

struct Visitor : public hilti::visitor::PreOrder<void, Visitor> {
    explicit Visitor(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;
    bool modified = false;

#if 0
    std::set<Node*> seen;

    void preDispatch(const Node& n, int level) override {
        std::string prefix = "# ";

        if ( seen.find(&n) != seen.end() )
            prefix = "! ";
        else
            seen.insert(&n);

        auto indent = std::string(level * 2, ' ');
        std::cerr << prefix << indent << "> " << n.render() << std::endl;
        n.scope()->render(std::cerr, "    | ");
    };
#endif

    // Log debug message recording resolving a expression.
    void logChange(const Node& old, const Expression& nexpr) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> expression %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a statement.
    void logChange(const Node& old, const Statement& nstmt) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> statement %s (%s)", old.typename_(), old, nstmt, old.location()));
    }

    // Log debug message recording resolving a type.
    void logChange(const Node& old, const Type& ntype, const char* msg = "type") {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> %s %s (%s)", old.typename_(), old, msg, ntype, old.location()));
    }

    // Log debug message recording resolving a unit item.
    void logChange(const Node& old, const type::unit::Item& i) {
        HILTI_DEBUG(logging::debug::Resolver,
                    hilti::util::fmt("[%s] %s -> %s (%s)", old.typename_(), old, i, old.location()));
    }

    void operator()(const Hook& h, position_t p) {
        if ( ! h.unitField() || h.ddRef() )
            return;

        std::optional<Type> dd;

        if ( h.isForEach() ) {
            if ( ! h.unitField()->ddRef() )
                return;

            dd = h.unitField()->ddType();
            if ( ! type::isResolved(*dd) )
                return;

            if ( ! type::isIterable(*dd) ) {
                p.node.addError("'foreach' hook can only be used with containers");
                return;
            }

            dd = dd->elementType();
        }
        else
            dd = h.unitField()->itemType();

        if ( dd.has_value() && type::isResolved(*dd) && ! dd->isA<type::Void>() ) {
            logChange(p.node, *dd, "$$ type");
            p.node.as<Hook>().setDDType(std::move(*dd));
            modified = true;
        }
    }

    void operator()(const type::bitfield::Bits& b, position_t p) {
        if ( type::isResolved(b.itemType()) )
            return;

        Type t = b.ddType();

        if ( auto a = AttributeSet::find(b.attributes(), "&convert") ) {
            t = a->valueAsExpression()->get().type();
            if ( ! type::isResolved(t) )
                return;
        }

        logChange(p.node, t, "item type");
        p.node.as<type::bitfield::Bits>().setItemType(t);
        modified = true;
    }

    void operator()(const type::Bitfield& b, position_t p) {
        if ( type::isResolved(b.type()) )
            return;

        std::vector<hilti::type::tuple::Element> elems;

        for ( const auto& bit : b.bits() ) {
            if ( ! type::isResolved(bit.itemType()) )
                return;

            elems.emplace_back(bit.id(), bit.itemType());
        }

        Type t = type::Tuple(std::move(elems), b.meta());
        assert(type::isResolved(t));
        logChange(p.node, t);
        p.node.as<type::Bitfield>().setType(t);
        modified = true;
    }

    void operator()(const type::unit::item::Field& f, position_t p) {
        if ( ! type::isResolved(f.parseType()) ) {
            if ( auto t = _fieldType(f, f.originalType(), FieldType::ParseType, f.isContainer(), f.meta()) ) {
                logChange(p.node, *t, "parse type");
                p.node.as<type::unit::item::Field>().setParseType(std::move(*t));
            }
        }

        if ( ! type::isResolved(f.ddType()) && type::isResolved(f.parseType()) ) {
            if ( auto dd = _fieldType(f, f.originalType(), FieldType::DDType, f.isContainer(), f.meta()) ) {
                if ( ! dd->isA<type::Void>() ) {
                    logChange(p.node, *dd, "$$ type");
                    p.node.as<type::unit::item::Field>().setDDType(std::move(*dd));
                    modified = true;
                }
            }
        }

        if ( ! type::isResolved(f.itemType()) && type::isResolved(f.parseType()) ) {
            std::optional<Type> t;

            if ( auto x = f.convertExpression() ) {
                if ( x->second ) {
                    // Unit-level convert on the sub-item.
                    auto u = x->second->as<type::Unit>();
                    auto a = AttributeSet::find(u.attributes(), "&convert");
                    assert(a);
                    auto e = a->valueAsExpression()->get();
                    if ( hilti::expression::isResolved(e) )
                        t = e.type();
                }
                else if ( hilti::expression::isResolved(x->first) ) {
                    t = x->first.type();

                    // If there's list comprehension, morph the type into a vector.
                    // Assignment will transparently work.
                    if ( auto x = t->tryAs<type::List>() )
                        t = hilti::type::Vector(x->elementType(), x->meta());
                }
            }
            else if ( const auto& i = f.item(); i && i->isA<type::unit::item::Field>() ) {
                const auto& inner_f = i->as<type::unit::item::Field>();
                t = _fieldType(inner_f, i->itemType(), FieldType::ItemType, f.isContainer(), f.meta());
            }
            else
                t = _fieldType(f, f.originalType(), FieldType::ItemType, f.isContainer(), f.meta());

            if ( t ) {
                logChange(p.node, *t, "item type");
                p.node.as<type::unit::item::Field>().setItemType(std::move(*t));
                modified = true;
            }
        }
    }

    void replaceField(position_t* p, const type::unit::Item& i) {
        logChange(p->node, i);
        p->node = i;
        modified = true;
    }

    void operator()(const type::unit::item::UnresolvedField& u, position_t p) {
        if ( u.type() && u.type()->isA<type::Void>() && u.attributes() ) {
            // Transparently map void fields that aim to parse data into
            // skipping bytes fields. Use of such void fields is deprecated and
            // will be removed later.
            int ok_attrs = 0;
            const auto& attrs = u.attributes()->attributes();
            for ( const auto& a : attrs ) {
                if ( a.tag() == "&requires" )
                    ok_attrs++;
            }

            if ( ok_attrs != attrs.size() ) {
                hilti::logger().deprecated(
                    "using `void` fields with attributes is deprecated and support will be removed in a future "
                    "release; replace 'void ...' with 'skip bytes ...'",
                    u.meta().location());

                p.node.as<type::unit::item::UnresolvedField>().setSkip(true);
                p.node.as<type::unit::item::UnresolvedField>().setType(type::Bytes());
            }
        }

        if ( const auto& id = u.unresolvedID() ) { // check for unresolved IDs first to overrides the other cases below
            auto resolved = hilti::scope::lookupID<hilti::Declaration>(*id, p, "field");
            if ( ! resolved ) {
                p.node.addError(resolved.error());
                return;
            }

            if ( auto t = resolved->first->tryAs<hilti::declaration::Type>() ) {
                Type tt = hilti::builder::typeByID(*id);

                // If a unit comes with a &convert attribute, we wrap it into a
                // subitem so that we have our recursive machinery available
                // (which we don't have for pure types).
                if ( auto unit_type = t->type().tryAs<type::Unit>();
                     unit_type && AttributeSet::has(unit_type->attributes(), "&convert") ) {
                    auto inner_field = type::unit::item::Field({}, std::move(tt), spicy::Engine::All, false,
                                                               u.arguments().copy(), {}, {}, {}, {}, {}, u.meta());
                    inner_field.setIndex(*u.index());

                    auto outer_field =
                        type::unit::item::Field(u.fieldID(), std::move(inner_field), u.engine(), u.isSkip(), {},
                                                u.repeatCount(), u.sinks().copy(), u.attributes(), u.condition(),
                                                u.hooks().copy(), u.meta());

                    outer_field.setIndex(*u.index());

                    replaceField(&p, std::move(outer_field));
                }

                else
                    // Default treatment for types is to create a corresponding field.
                    replaceField(&p, resolveField(u, NodeRef(resolved->first)));
            }

            else if ( auto c = resolved->first->tryAs<hilti::declaration::Constant>() ) {
                if ( auto ctor = c->value().tryAs<hilti::expression::Ctor>() )
                    replaceField(&p, resolveField(u, ctor->ctor()));
                else
                    p.node.addError("field value must be a constant");
            }
            else
                p.node.addError(hilti::util::fmt("field value must be a constant or type (but is a %s)",
                                                 resolved->first->as<hilti::Declaration>().displayName()));
        }

        else if ( auto c = u.ctor() )
            replaceField(&p, resolveField(u, *c));

        else if ( auto t = u.type() ) {
            if ( ! type::isResolved(t) )
                return;

            replaceField(&p, resolveField(u, *t));
        }

        else if ( auto i = u.item() )
            replaceField(&p, resolveField(u, *i));

        else
            hilti::logger().internalError("no known type for unresolved field", p.node.location());
    }

    void operator()(const hilti::expression::UnresolvedID& x, position_t p) {
        // Allow `$$` as an alias for `self` in unit convert attributes for symmetry with field convert attributes.
        if ( x.id() == ID("__dd") ) {
            // The following loop searches for `&convert` attribute nodes directly under `Unit` nodes.
            for ( size_t parent_nr = 1; parent_nr < p.pathLength(); ++parent_nr ) {
                auto attr = p.parent(parent_nr).tryAs<Attribute>();

                if ( ! attr )
                    continue;

                if ( attr->tag() != "&convert" )
                    return;

                // The direct parent of the attribute set containing the attribute should be the unit.
                if ( ! p.parent(parent_nr + 2).isA<type::Unit>() )
                    return;

                p.node = hilti::builder::id("self");
                modified = true;
            }
        }
    }
};

} // anonymous namespace

bool spicy::detail::ast::resolve(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit) {
    bool hilti_modified = (*hilti::plugin::registry().hiltiPlugin().ast_resolve)(ctx, root, unit);

    hilti::util::timing::Collector _("spicy/compiler/resolver");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified || hilti_modified;
}
