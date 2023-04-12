// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/base/logger.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/unit.h>

#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-items/unit-hook.h>
#include <spicy/ast/types/unit-items/variable.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace {

struct Visitor : public hilti::visitor::PostOrder<void, Visitor> {
    explicit Visitor(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;

    void operator()(const type::Unit& t, position_t p) {
        if ( auto d = t.selfRef() )
            p.node.scope()->insert(std::move(d));

        for ( auto&& x : t.parameterRefs() )
            p.node.scope()->insert(std::move(x));
    }

    void operator()(const type::bitfield::Bits& b, position_t p) {
        if ( auto d = b.ddRef() )
            p.node.scope()->insert(std::move(d));
    }

    void operator()(const type::unit::item::Field& f, position_t p) {
        if ( auto d = f.ddRef() )
            p.node.scope()->insert(std::move(d));
    }

    void operator()(const declaration::UnitHook& h, position_t p) {
        if ( auto d = h.hook().ddRef() )
            p.node.scope()->insert(std::move(d));

        if ( auto u = h.hook().unitType() ) {
            if ( u->selfRef() )
                p.node.scope()->insert(u->selfRef());

            for ( auto&& x : u->parameterRefs() )
                p.node.scope()->insert(std::move(x));
        }
    }

    void operator()(const Hook& h, position_t p) {
        if ( auto d = h.ddRef() )
            p.node.scope()->insert(std::move(d));
        else
            // Force the scope lookup to stop here so that we don't find any
            // higher-level `$$`, which may have a different type.
            p.node.scope()->insertNotFound(ID("__dd"));

        for ( auto&& x : h.ftype().parameterRefs() )
            p.node.scope()->insert(std::move(x));

        if ( auto u = h.unitType() ) {
            if ( u->selfRef() )
                p.node.scope()->insert(u->selfRef());

            for ( auto&& x : u->parameterRefs() )
                p.node.scope()->insert(std::move(x));
        }
    }

    void operator()(const hilti::Attribute& a, position_t p) {
        if ( a.tag() == "&until" || a.tag() == "&until-including" || a.tag() == "&while" ) {
            auto f = p.findParent<type::unit::item::Field>();
            if ( ! (f && f->get().isContainer()) )
                return;

            const auto& pt = f->get().parseType();
            if ( ! type::isResolved(pt) )
                return;

            auto dd = hilti::expression::Keyword::createDollarDollarDeclaration(pt.elementType());
            auto n = unit->module().as<Module>().preserve(std::move(dd));
            p.node.scope()->insert(std::move(n));
        }
    }
};

} // anonymous namespace

void spicy::detail::ast::buildScopes(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit) {
    (*hilti::plugin::registry().hiltiPlugin().ast_build_scopes)(ctx, root, unit);

    hilti::util::timing::Collector _("spicy/compiler/ast/scope-builder");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);
}
