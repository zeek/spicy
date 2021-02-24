// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/types/id.h>
#include <hilti/ast/types/reference.h>
#include <hilti/global.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/unresolved-field.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace {

inline const hilti::logging::DebugStream Resolver("resolver");

// Turns an unresolved field into a resolved field.
template<typename T>
auto resolveField(const type::unit::item::UnresolvedField& u, const T& t) {
    auto field = type::unit::item::Field(u.fieldID(), std::move(t), u.engine(), u.arguments(), u.repeatCount(),
                                         u.sinks(), u.attributes(), u.condition(), u.hooks(), u.meta());

    assert(u.index());
    return type::unit::item::Field::setIndex(std::move(field), *u.index());
}

struct Visitor1 : public hilti::visitor::PostOrder<void, Visitor1> {
    explicit Visitor1(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;
    bool modified = false;

    template<typename T>
    void replaceNode(position_t* p, T&& n, int line) {
        p->node = std::forward<T>(n);
        HILTI_DEBUG(Resolver, hilti::util::fmt("  modified by Spicy %s:%d",
                                               hilti::rt::filesystem::path(__FILE__).filename().native(), line))
        modified = true;
    }

    void replaceUnresolvedField(const type::unit::item::UnresolvedField& u, position_t p) {
        if ( auto id = u.unresolvedID() ) { // check for unresolved IDs first to overrides the other cases below
            auto resolved = hilti::scope::lookupID<hilti::Declaration>(*id, p, "field");

            if ( ! resolved ) {
                p.node.addError(resolved.error());
                return;
            }

            if ( auto t = resolved->first->tryAs<hilti::declaration::Type>() ) {
                auto unit_type = t->type().tryAs<type::Unit>();

                if ( ! unit_type && t->type().originalNode() )
                    unit_type = t->type().originalNode()->tryAs<type::Unit>();

                // Because we're doing type resolution ourselves here, we
                // need to account for any &on-heap attribute. Normally,
                // HILTI would take care of that for us when resolving a
                // type.
                Type tt = hilti::type::ResolvedID(*id, NodeRef(resolved->first), u.meta());

                if ( unit_type || AttributeSet::has(t->attributes(), "&on-heap") )
                    tt = hilti::type::ValueReference(tt, u.meta());

                // If a unit comes with a &convert attribute, we wrap it into a
                // subitem so that  we have our recursive machinery available
                // (which we don't have for pure types).
                if ( unit_type && AttributeSet::has(unit_type->attributes(), "&convert") ) {
                    auto inner_field = type::unit::item::Field({}, std::move(tt), spicy::Engine::All, u.arguments(), {},
                                                               {}, {}, {}, {}, u.meta());
                    inner_field = type::unit::item::Field::setIndex(std::move(inner_field), *u.index());

                    auto outer_field =
                        type::unit::item::Field(u.fieldID(), std::move(inner_field), u.engine(), {}, u.repeatCount(),
                                                u.sinks(), u.attributes(), u.condition(), u.hooks(), u.meta());

                    outer_field = type::unit::item::Field::setIndex(std::move(outer_field), *u.index());
                    replaceNode(&p, std::move(outer_field), __LINE__);
                }

                else
                    // Default treatment for types is to create a corresponding field.
                    replaceNode(&p, resolveField(u, std::move(tt)), __LINE__);
            }

            else if ( auto c = resolved->first->tryAs<hilti::declaration::Constant>() ) {
                if ( auto ctor = c->value().tryAs<hilti::expression::Ctor>() )
                    replaceNode(&p, resolveField(u, ctor->ctor()), __LINE__);
                else
                    p.node.addError("field value must be a constant");
            }
            else
                p.node.addError(hilti::util::fmt("field value must be a constant or type (but is a %s)",
                                                 resolved->first->as<hilti::Declaration>().displayName()));
        }

        else if ( auto c = u.ctor() )
            replaceNode(&p, resolveField(u, *c), __LINE__);

        else if ( auto t = u.type() )
            replaceNode(&p, resolveField(u, *t), __LINE__);

        else if ( auto i = u.item() ) {
            auto f = resolveField(u, *i);
            replaceNode(&p, f, __LINE__);
        }
        else
            hilti::logger().internalError("no known type for unresolved field", p.node.location());
    }

    void operator()(const type::unit::item::UnresolvedField& u, position_t p) { replaceUnresolvedField(u, p); }

    void operator()(const type::Unit& n, position_t p) {
        if ( auto t = p.parent().tryAs<hilti::declaration::Type>();
             ! t && ! p.parent(2).tryAs<hilti::declaration::Type>() )
            replaceNode(&p, hilti::type::UnresolvedID(*n.typeID(), p.node.meta()), __LINE__);
    }
};

struct Visitor2 : public hilti::visitor::PostOrder<void, Visitor2> {
    explicit Visitor2(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;
    bool modified = false;

    template<typename T>
    void replaceNode(position_t* p, T&& n, int line) {
        p->node = std::forward<T>(n);
        HILTI_DEBUG(Resolver, hilti::util::fmt("  modified by Spicy %s:%d",
                                               hilti::rt::filesystem::path(__FILE__).filename().native(), line))
        modified = true;
    }

    void operator()(const hilti::expression::Keyword& n, position_t p) {
        if ( n.kind() == hilti::expression::keyword::Kind::DollarDollar && ! n.isSet() ) {
            std::optional<Type> dd;

            if ( auto f = p.findParent<hilti::Function>() ) {
                for ( const auto& p : f->get().type().parameters() ) {
                    if ( p.id() == ID("__dd") ) {
                        // Inside a free function that defines a "__dd" parameter; use it.
                        dd = type::Computed(hilti::builder::id("__dd"));
                        break;
                    }
                }
            }

            if ( ! dd ) {
                auto f = p.findParent<type::unit::item::Field>();

                if ( ! f )
                    return;

                if ( auto t = p.findParent<spicy::Hook>() ) {
                    // Inside a field's hook.
                    if ( t->get().isForEach() )
                        dd = type::unit::item::Field::vectorElementTypeThroughSelf(f->get().id());
                    else
                        dd = f->get().itemType();
                }

                else if ( auto a = p.findParent<Attribute>() ) {
                    // Inside an attribute expression.
                    if ( a->get().tag() == "&until" || a->get().tag() == "&until-including" ||
                         a->get().tag() == "&while" )
                        dd = type::unit::item::Field::vectorElementTypeThroughSelf(f->get().id());
                    else {
                        dd = f->get().parseType();

                        if ( auto bf = dd->tryAs<type::Bitfield>() )
                            dd = type::UnsignedInteger(bf->width(), bf->meta());
                    }
                }
            }

            if ( dd )
                replaceNode(&p,
                            hilti::expression::Keyword(hilti::expression::keyword::Kind::DollarDollar, *dd,
                                                       p.node.meta()),
                            __LINE__);
            else {
                p.node.addError("$$ not supported here");
                return;
            }
        }
    }

    void operator()(const type::Unit& n, position_t p) {
        if ( auto t = p.parent().tryAs<hilti::declaration::Type>();
             ! t && ! p.parent(2).tryAs<hilti::declaration::Type>() )
            replaceNode(&p, hilti::type::UnresolvedID(*n.typeID(), p.node.meta()), __LINE__);
    }
};

} // anonymous namespace

bool spicy::detail::resolveIDs(hilti::Node* root, hilti::Unit* unit) {
    hilti::util::timing::Collector _("spicy/compiler/id-resolver");

    auto v1 = Visitor1(unit);
    for ( auto i : v1.walk(root) )
        v1.dispatch(i);

    auto v2 = Visitor2(unit);
    for ( auto i : v2.walk(root) )
        v2.dispatch(i);

    return v1.modified || v2.modified;
}
