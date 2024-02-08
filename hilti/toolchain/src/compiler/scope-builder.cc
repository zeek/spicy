// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/list-comprehension.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/scope-builder.h>

using namespace hilti;

namespace {

struct Visitor : visitor::PostOrder {
    explicit Visitor(Builder* builder, const ASTRootPtr& root) : root(root), builder(builder) {}

    const ASTRootPtr& root;
    Builder* builder;

    void operator()(declaration::Constant* n) final { n->parent()->getOrCreateScope()->insert(n->as<Declaration>()); }

    void operator()(declaration::Expression* n) final { n->parent()->getOrCreateScope()->insert(n->as<Declaration>()); }

    void operator()(declaration::Function* n) final {
        auto x = n->parent();

        auto module = n->parent<declaration::Module>();
        assert(module);

        if ( ! n->id().namespace_() || n->id().namespace_() == module->id().namespace_() )
            x->getOrCreateScope()->insert(n->id().local(), n->as<Declaration>());

        for ( auto x : n->function()->ftype()->parameters() )
            n->getOrCreateScope()->insert(std::move(x));

        if ( n->linkage() == declaration::Linkage::Struct ) {
            if ( ! n->id().namespace_() ) {
                n->addError("method lacks a type namespace");
                return;
            }
        }

        if ( n->linkedDeclarationIndex() ) {
            if ( auto decl = builder->context()->lookup(n->linkedDeclarationIndex())->as<declaration::Type>() ) {
                const auto t = decl->type()->type()->as<type::Struct>();
                n->getOrCreateScope()->insert(t->self());

                for ( auto x : t->parameters() )
                    n->getOrCreateScope()->insert(std::move(x));
            }
        }
    }

    void operator()(declaration::GlobalVariable* n) final {
        if ( n->parent()->isA<declaration::Module>() )
            n->parent()->getOrCreateScope()->insert(n->as<declaration::GlobalVariable>());
    }

    void operator()(declaration::ImportedModule* n) final {
        // If we know the imported module already, insert it into the
        // containing module's scope so that we can look it up.
        if ( auto uid = n->uid() ) {
            auto imported_module = builder->context()->module(*uid);
            assert(imported_module);
            if ( auto index = imported_module->declarationIndex() ) {
                auto current_module = n->parent<declaration::Module>();
                assert(current_module);

                auto decl = builder->context()->lookup(index)->as<declaration::Module>();
                current_module->getOrCreateScope()->insert(decl);
            }
        }
    }

    void operator()(declaration::Module* n) final {
        auto m = n->as<declaration::Module>();

        // Insert into the module's own scope so that IDs inside the module can
        // be qualified with the module's own name. We insert it under
        // user-visible ID, even though declaration itself uses the unique ID
        // as its ID.
        n->getOrCreateScope()->insert(m->scopeID(), m);

        // Also insert the module name into the global scope. We need this for
        // global look-ups that aren't associated with a specific location
        // inside the AST (like when resolving operator signatures).
        root->getOrCreateScope()->insert(m->scopeID(), m);
    }

    void operator()(declaration::Type* n) final {
        if ( n->parent()->isA<declaration::Module>() )
            n->parent()->getOrCreateScope()->insert(n->as<declaration::Type>());
    }

    void operator()(declaration::Field* n) final {
        if ( auto func = n->inlineFunction() ) {
            for ( auto x : func->ftype()->parameters() )
                n->getOrCreateScope()->insert(std::move(x));
        }

        if ( n->isStatic() )
            // Insert static member into struct's namespace.
            n->parent(3)->getOrCreateScope()->insert(n->as<Declaration>());
    }

    void operator()(expression::ListComprehension* n) final { n->getOrCreateScope()->insert(n->local()); }

    void operator()(statement::Declaration* n) final { n->parent()->getOrCreateScope()->insert(n->declaration()); }

    void operator()(statement::For* n) final { n->getOrCreateScope()->insert(n->local()); }

    void operator()(statement::If* n) final {
        if ( n->init() )
            n->getOrCreateScope()->insert(n->init());
    }

    void operator()(statement::Switch* n) final { n->getOrCreateScope()->insert(n->condition()); }

    void operator()(statement::try_::Catch* n) final {
        if ( auto x = n->parameter() )
            n->getOrCreateScope()->insert(std::move(x));
    }

    void operator()(statement::While* n) final {
        if ( auto x = n->init() )
            n->getOrCreateScope()->insert(std::move(x));
    }

    void operator()(type::bitfield::BitRange* n) final {
        if ( auto d = n->dd() )
            n->scope()->insert(std::move(d));
    }

    void operator()(type::Enum* n) final {
        if ( ! n->parent(2)->isA<declaration::Type>() )
            return;

        if ( ! n->typeID() )
            return;

        for ( auto&& d : n->as<type::Enum>()->labelDeclarations() ) {
            n->parent(2)->getOrCreateScope()->insert(std::move(d));
        }
    }

    void operator()(type::Struct* n) final {
        for ( auto x : n->parameters() )
            n->getOrCreateScope()->insert(std::move(x));

        if ( n->typeID() )
            // We need to associate the type ID with the `self` declaration,
            // so wait for that to have been set by the resolver.
            n->getOrCreateScope()->insert(n->self());
    }
};

} // anonymous namespace

void detail::scope_builder::build(Builder* builder, const ASTRootPtr& root) {
    util::timing::Collector _("hilti/compiler/ast/scope-builder");
    ::hilti::visitor::visit(Visitor(builder, root), root);
}
