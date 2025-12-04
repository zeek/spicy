// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ast-context.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/scope-builder.h>

using namespace spicy;

namespace {

struct VisitorScopeBuilder : visitor::PostOrder {
    explicit VisitorScopeBuilder(Builder* builder, hilti::ASTRoot* root) : root(root), builder(builder) {}

    hilti::ASTRoot* root = nullptr;
    Builder* builder;

    void operator()(type::Unit* n) final {
        if ( auto* d = n->self() )
            n->getOrCreateScope()->insert(d);

        for ( auto&& x : n->parameters() )
            n->getOrCreateScope()->insert(x);
    }

    void operator()(type::unit::item::Field* n) final {
        if ( auto* d = n->dd() )
            n->getOrCreateScope()->insert(d);
    }

    void operator()(declaration::UnitHook* n) final {
        if ( auto* d = n->hook()->dd() )
            n->getOrCreateScope()->insert(d);

        if ( auto* t = builder->context()->lookup(n->hook()->unitTypeIndex()) ) {
            auto* u = t->as<type::Unit>();
            if ( u->self() )
                n->getOrCreateScope()->insert(u->self());

            for ( auto&& x : u->parameters() )
                n->getOrCreateScope()->insert(x);
        }
    }

    void operator()(declaration::Hook* n) final {
        if ( auto* d = n->dd() )
            n->getOrCreateScope()->insert(d);
        else
            // Force the scope lookup to stop here so that we don't find any
            // higher-level `$$`, which may have a different type.
            n->getOrCreateScope()->insertNotFound(ID(HILTI_INTERNAL_ID("dd")));

        for ( auto&& x : n->ftype()->parameters() )
            n->getOrCreateScope()->insert(x);

        if ( auto* t = builder->context()->lookup(n->unitTypeIndex()) ) {
            auto* u = t->as<type::Unit>();
            if ( u->self() )
                n->getOrCreateScope()->insert(u->self());

            for ( auto&& x : u->parameters() )
                n->getOrCreateScope()->insert(x);
        }
    }

    void operator()(hilti::Attribute* n) final {
        if ( hilti::attribute::isOneOf(n->kind(), {attribute::kind::Until, attribute::kind::UntilIncluding,
                                                   attribute::kind::While}) ) {
            auto* f = n->parent<type::unit::item::Field>();
            if ( ! (f && f->isContainer()) )
                return;

            const auto& pt = f->parseType();
            if ( ! pt->isResolved() )
                return;

            auto* dd = hilti::expression::Keyword::createDollarDollarDeclaration(builder->context(),
                                                                                 pt->type()->elementType());
            n->getOrCreateScope()->insert(dd);
        }
    }
};

} // anonymous namespace

void detail::scope_builder::build(Builder* builder, hilti::ASTRoot* root) {
    hilti::util::timing::Collector _("spicy/compiler/ast/scope-builder");

    (*hilti::plugin::registry().hiltiPlugin().ast_build_scopes)(builder, root);
    hilti::visitor::visit(VisitorScopeBuilder(builder, root), root, ".spicy");
}
