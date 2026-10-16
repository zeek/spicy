// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <set>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>

#include <spicy/ast/attribute.h>
#include <spicy/ast/builder/builder.h>
#include <spicy/ast/declarations/hook.h>
#include <spicy/ast/operators/unit.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/optimizer.h>

using namespace spicy;
using namespace spicy::detail;

namespace {

// Returns the canonical ID of the unit that directly contains a field,
// walking up through switch/block containers.
ID unitCanonicalIDForField(const type::unit::item::Field* f) {
    for ( auto* n = f->parent(); n; n = n->parent() ) {
        if ( auto* unit = n->tryAs<type::Unit>() )
            return unit->canonicalID();
    }
    return {};
}

// Records (unit_canonical_id, field_id) pairs that are accessed.
struct AccessCollector : public visitor::PreOrder {
    explicit AccessCollector(Builder* builder) : builder(builder) {}

    Builder* builder;
    std::set<std::pair<ID, ID>> accessed;

    void markFieldAccess(type::Unit* unit, const ID& id) {
        if ( unit->itemByName(id) )
            accessed.emplace(unit->canonicalID(), id);
    }

    void markAllFields(type::Unit* unit) {
        // Mark every named field in the unit as accessed, including those
        // inside switch cases (they share the same canonical unit ID).
        for ( auto* item : unit->items() ) {
            if ( auto* f = item->tryAs<type::unit::item::Field>() )
                accessed.emplace(unit->canonicalID(), f->id());

            if ( auto* sw = item->tryAs<type::unit::item::Switch>() ) {
                for ( const auto* c : sw->cases() )
                    for ( auto* si : c->block()->allItems() )
                        if ( auto* f = si->tryAs<type::unit::item::Field>() )
                            accessed.emplace(unit->canonicalID(), f->id());
            }
        }
    }

    void operator()(operator_::unit::MemberConst* n) final {
        if ( auto* unit = n->op0()->type()->type()->tryAs<type::Unit>() )
            markFieldAccess(unit, n->op1()->as<hilti::expression::Member>()->id());
    }

    void operator()(operator_::unit::MemberNonConst* n) final {
        if ( auto* unit = n->op0()->type()->type()->tryAs<type::Unit>() )
            markFieldAccess(unit, n->op1()->as<hilti::expression::Member>()->id());
    }

    void operator()(operator_::unit::TryMember* n) final {
        if ( auto* unit = n->op0()->type()->type()->tryAs<type::Unit>() )
            markFieldAccess(unit, n->op1()->as<hilti::expression::Member>()->id());
    }

    void operator()(operator_::unit::HasMember* n) final {
        if ( auto* unit = n->op0()->type()->type()->tryAs<type::Unit>() )
            markFieldAccess(unit, n->op1()->as<hilti::expression::Member>()->id());
    }

    void operator()(hilti::expression::Name* n) final {
        if ( n->id() != ID("self") )
            return;

        // A `self` name that resolves to the self-declaration of a unit but is
        // not a targeted field access (i.e., it's used as a whole value, e.g.
        // in `print self` or passed to a function): conservatively mark every
        // field of that unit as accessed.
        auto* p = n->parent();
        if ( ! p )
            return;
        if ( p->isA<operator_::unit::MemberConst>() || p->isA<operator_::unit::MemberNonConst>() ||
             p->isA<operator_::unit::TryMember>() || p->isA<operator_::unit::HasMember>() ||
             p->isA<operator_::unit::Unset>() )
            return;

        auto* resolved = n->resolvedDeclaration();
        if ( ! resolved )
            return;

        // The resolved declaration should be the `declaration::Expression(ID("self"), Keyword::Self)`
        // node synthesized in the unit scope; look through it to get the unit type.
        auto* self_decl = resolved->tryAs<hilti::declaration::Expression>();
        if ( ! self_decl )
            return;

        if ( auto* unit = self_decl->expression()->type()->type()->tryAs<type::Unit>() )
            markAllFields(unit);
    }

    void operator()(declaration::Hook* n) final {
        if ( ! n->unitFieldIndex() )
            return;

        // Skip auto-generated empty hooks (e.g., `_t_on_x`); only
        // user-written hooks with a body constitute a real field access.
        if ( n->body()->statements().empty() )
            return;

        auto* decl = builder->context()->lookup(n->unitFieldIndex());
        if ( auto* field = decl->tryAs<type::unit::item::Field>() ) {
            auto unit_id = unitCanonicalIDForField(field);
            if ( unit_id )
                accessed.emplace(unit_id, field->id());
        }
    }
};

struct SkipMarker : public visitor::PreOrder {
    explicit SkipMarker(Builder* builder, const std::set<std::pair<ID, ID>>& accessed)
        : builder(builder), accessed(accessed) {}

    Builder* builder;
    const std::set<std::pair<ID, ID>>& accessed;
    bool modified = false;

    void operator()(type::unit::item::Field* f) final {
        if ( f->isAnonymous() || f->isSkip() )
            return;

        // Inline hooks receive $$ (the field value), so skip marking is
        // unsafe: the hook call convention would change.
        if ( ! f->hooks().empty() )
            return;

        // Sink connections forward $$ to the sink; skipping the field drops the data.
        if ( ! f->sinks().empty() )
            return;

        // &requires uses $$ — skip marking changes its codegen.
        if ( f->attributes()->find(attribute::kind::Requires) )
            return;

        auto unit_id = unitCanonicalIDForField(f);
        if ( ! unit_id )
            return;

        if ( accessed.contains({unit_id, f->id()}) )
            return;

        if ( auto* convert = f->attributes()->find(attribute::kind::Convert) ) {
            // Field -> Block -> Case -> Switch: exactly three levels up.
            auto* p = f->parent();
            bool in_switch =
                p && p->parent() && p->parent()->parent() && p->parent()->parent()->isA<type::unit::item::Switch>();
            if ( in_switch )
                // Preserve the &convert for switch type unification but replace its
                // expression with default<ItemType>() so no $$ reference remains.
                convert->replaceChild(builder->context(), convert->value(), builder->default_(f->itemType()->type()));
            else
                f->attributes()->remove(attribute::kind::Convert); // noop if absent
        }

        HILTI_DEBUG(spicy::logging::debug::Optimizer,
                    hilti::util::fmt("marking field '%s' as skip", f->fullyQualifiedID()));
        f->setSkip(true);
        modified = true;
    }
};

} // namespace

bool optimizer::optimize(Builder* builder, hilti::ASTRoot* root) {
    if ( builder->options().public_api_mode == hilti::Options::PublicAPIMode::Strict )
        return false;

    AccessCollector collector(builder);
    visitor::visit(collector, root, ".spicy");

    SkipMarker marker(builder, collector.accessed);
    visitor::visit(marker, root, ".spicy");

    return marker.modified;
}
