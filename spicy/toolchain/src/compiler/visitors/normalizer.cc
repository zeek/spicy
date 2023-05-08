// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Normalizer("normalizer");
} // namespace hilti::logging::debug

namespace {

struct Visitor : public hilti::visitor::PostOrder<void, Visitor> {
    explicit Visitor(Node* root) : root(root) {}
    Node* root;
    bool modified = false;

    // Log debug message recording resolving a expression.
    void logChange(const Node& old, const Expression& nexpr) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> expression %s (%s)", old.typename_(), old, nexpr, old.location()));
    }

    // Log debug message recording resolving a statement.
    void logChange(const Node& old, const Statement& nstmt) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> statement %s (%s)", old.typename_(), old, nstmt, old.location()));
    }

    // Log debug message recording resolving a type.
    void logChange(const Node& old, const Type& ntype, const char* msg = "type") {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> %s %s (%s)", old.typename_(), old, msg, ntype, old.location()));
    }

    void logChange(const Node& old, const std::string_view msg) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> %s (%s)", old.typename_(), old, msg, old.location()));
    }

    // Log debug message recording resolving a unit item.
    void logChange(const Node& old, const type::unit::Item& i) {
        HILTI_DEBUG(hilti::logging::debug::Normalizer,
                    hilti::util::fmt("[%s] %s -> %s (%s)", old.typename_(), old, i, old.location()));
    }

    void operator()(const Module& m, position_t p) {
        // Because we alias some Spicy types to HILTI types, we need to make
        // the HILTI library available.
        if ( m.id() == ID("spicy_rt") || m.id() == ID("hilti") )
            return;

        bool have_hilti_import = false;

        for ( const auto& d : m.declarations() ) {
            if ( auto i = d.tryAs<hilti::declaration::ImportedModule>(); i && i->id() == ID("spicy_rt") )
                have_hilti_import = true;
        }

        if ( ! have_hilti_import ) {
            // Import "spicy_rt", which uses HILTI syntax, so we need to set
            // the parsing extension to ".hlt". We then however process it as
            // an Spicy AST, so that it participates in our resolving.
            logChange(p.node, "import spicy_rt & hilti");
            p.node.as<Module>().add(hilti::builder::import("spicy_rt", ".hlt"));
            p.node.as<Module>().add(hilti::builder::import("hilti", ".hlt"));
            modified = true;
        }
    }

    void operator()(const hilti::declaration::Type& t, position_t p) {
        if ( auto u = t.type().tryAs<type::Unit>() ) {
            if ( t.linkage() == declaration::Linkage::Public && ! u->isPublic() ) {
                logChange(p.node, "set public");
                const_cast<type::Unit&>(t.type().as<type::Unit>()).setPublic(true);
                modified = true;
            }

            // Create unit property items from global module items where the unit
            // does not provide an overriding one.
            std::vector<type::unit::Item> ni;
            for ( const auto& prop : root->as<Module>().moduleProperties({}) ) {
                if ( u->propertyItem(prop.id()) )
                    continue;

                auto i = type::unit::item::Property(prop.id(), *prop.expression(), {}, true, prop.meta());
                logChange(p.node, hilti::util::fmt("add module-level property %s", prop.id()));
                const_cast<type::Unit&>(t.type().as<type::Unit>()).addItems({std::move(i)});
                modified = true;
            }
        }
    }

    void operator()(const Hook& h, position_t p) {
        if ( h.unitType() && h.unitField() )
            return;

        // A`%print` hook returns a string as the rendering to print, need
        // to adjust its return type, which defaults to void.
        if ( h.id().local().str() == "0x25_print" ) {
            if ( h.ftype().result().type().isA<type::Void>() ) {
                logChange(p.node, "setting %print result to string");
                p.node.as<Hook>().setResultType(type::Optional(type::String()));
                modified = true;
            }
        }

        // If an `%error` hook doesn't provide the optional string argument,
        // add it here so that we can treat the two versions the same.
        if ( h.id().local().str() == "0x25_error" ) {
            auto params = h.ftype().parameters();
            if ( params.size() == 0 ) {
                logChange(p.node, "adding parameter to %error");
                p.node.as<Hook>().setParameters({hilti::builder::parameter("__except", type::String())});
                modified = true;
            }
        }

        // Link hook to its unit type and field.

        NodeRef unit_type_ref = p.findParentRef<type::Unit>();
        if ( ! unit_type_ref ) {
            // External hook, do name lookuo.
            auto ns = h.id().namespace_();
            if ( ! ns )
                return;

            auto resolved = hilti::scope::lookupID<hilti::declaration::Type>(ns, p, "unit type");
            if ( ! resolved ) {
                p.node.addError(resolved.error());
                return;
            }

            unit_type_ref = resolved->first->as<hilti::declaration::Type>().typeRef();
        }

        assert(unit_type_ref);

        if ( ! h.unitType() ) {
            logChange(p.node, unit_type_ref->as<Type>(), "unit type");
            p.node.as<Hook>().setUnitTypeRef(NodeRef(unit_type_ref));
            modified = true;
        }

        NodeRef unit_field_ref = p.findParentRef<type::unit::item::Field>();
        if ( ! unit_field_ref ) {
            // External or out-of-line hook.
            if ( ! h.id() ) {
                p.node.addError("hook name missing");
                return;
            }

            unit_field_ref = unit_type_ref->as<type::Unit>().itemRefByName(h.id().local());
            if ( ! unit_field_ref )
                // We do not record an error here because we'd need to account
                // for %init/%done/etc. We'll leave that to the validator.
                return;

            if ( ! unit_field_ref->isA<type::unit::item::Field>() ) {
                p.node.addError(hilti::util::fmt("'%s' is not a unit field", h.id()));
                return;
            }
        }

        assert(unit_field_ref);

        if ( unit_field_ref->isA<type::unit::item::Field>() && ! h.unitField() ) {
            logChange(p.node, unit_field_ref->as<type::unit::Item>());
            p.node.as<Hook>().setFieldRef(std::move(unit_field_ref));
            modified = true;
        }
    }

    void operator()(const hilti::expression::Assign& assign, position_t p) {
        // Rewrite assignments involving unit fields to use the non-const member operator.
        if ( auto member_const = assign.children().front().tryAs<operator_::unit::MemberConst>() ) {
            auto new_lhs = operator_::unit::MemberNonConst::Operator().instantiate(member_const->operands().copy(),
                                                                                   member_const->meta());
            Expression n = hilti::expression::Assign(new_lhs, assign.source(), assign.meta());
            logChange(p.node, n);
            p.node = n;
            modified = true;
            return;
        }
    }

    void operator()(const type::Unit& u, position_t p) {
        if ( ! p.node.as<Type>().typeID() )
            return;

        if ( ! u.selfRef() )
            type::Unit::setSelf(&p.node);

        const auto& t = p.node.as<Type>();

        if ( ! t.hasFlag(type::Flag::NoInheritScope) ) {
            logChange(p.node, "set no-inherit");
            p.node.as<Type>().addFlag(type::Flag::NoInheritScope);
            modified = true;
        }

        if ( t.typeID() && ! u.id() ) {
            logChange(p.node, hilti::util::fmt("unit ID %s", *t.typeID()));
            p.node.as<type::Unit>().setID(*t.typeID());
            modified = true;
        }
    }

    void operator()(const type::unit::item::Field& f, position_t p) {
        if ( (f.isAnonymous() || f.isSkip()) && ! f.isTransient() ) {
            // Make the field transient if it's either top-level, or a direct
            // parent field is already transient.
            bool make_transient = false;

            if ( p.parent().isA<type::Unit>() )
                make_transient = true;

            if ( auto pf = p.findParent<type::unit::item::Field>(); pf && pf->get().isTransient() )
                make_transient = true;

            if ( make_transient ) {
                // Make anonymous top-level fields transient.
                logChange(p.node, "set transient");
                p.node.as<type::unit::item::Field>().setTransient(true);
                modified = true;
            }
        }
    }
};

} // anonymous namespace

bool spicy::detail::ast::normalize(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit) {
    bool hilti_modified = (*hilti::plugin::registry().hiltiPlugin().ast_normalize)(ctx, root, unit);

    hilti::util::timing::Collector _("spicy/compiler/normalizer");

    auto v = Visitor(root);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified || hilti_modified;
}
