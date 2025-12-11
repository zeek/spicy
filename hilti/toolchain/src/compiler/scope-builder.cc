// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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
    explicit Visitor(Builder* builder, Node* root) : root(root), builder(builder) {}

    Node* root = nullptr;
    Builder* builder;

    bool modified = false;

    void operator()(declaration::Constant* n) final { modified |= n->parent()->getOrCreateScope()->insert(n); }

    void operator()(declaration::Expression* n) final { modified |= n->parent()->getOrCreateScope()->insert(n); }

    void operator()(declaration::Function* n) final {
        auto* x = n->parent();

        auto* module = n->parent<declaration::Module>();
        assert(module);

        // Grab the body's scope if available
        auto* scope = n->function()->body() ? n->function()->body()->getOrCreateScope() : n->getOrCreateScope();

        if ( ! n->id().namespace_() || n->id().namespace_() == module->id().namespace_() )
            modified |= x->getOrCreateScope()->insert(n->id().local(), n);

        for ( auto* x : n->function()->ftype()->parameters() )
            modified |= scope->insert(x);

        if ( n->linkage() == declaration::Linkage::Struct ) {
            if ( ! n->id().namespace_() ) {
                n->addError("method lacks a type namespace");
                return;
            }
        }

        if ( n->linkedDeclarationIndex() ) {
            if ( auto* decl = builder->context()->lookup(n->linkedDeclarationIndex())->as<declaration::Type>() ) {
                auto* const t = decl->type()->type()->as<type::Struct>();
                modified |= scope->insert(t->self());

                for ( auto* x : t->parameters() )
                    modified |= scope->insert(x);
            }
        }
    }

    void operator()(declaration::GlobalVariable* n) final {
        if ( n->parent()->isA<declaration::Module>() )
            modified |= n->parent()->getOrCreateScope()->insert(n);
    }

    void operator()(declaration::ImportedModule* n) final {
        // If we know the imported module already, insert it into the
        // containing module's scope so that we can look it up.
        if ( const auto& uid = n->uid() ) {
            auto* imported_module = builder->context()->module(*uid);
            assert(imported_module);
            if ( auto index = imported_module->declarationIndex() ) {
                auto* current_module = n->parent<declaration::Module>();
                assert(current_module);

                auto* decl = builder->context()->lookup(index)->as<declaration::Module>();
                modified |= current_module->getOrCreateScope()->insert(decl);
            }
        }
    }

    void operator()(declaration::Module* n) final {
        auto* m = n;

        // Insert into the module's own scope so that IDs inside the module can
        // be qualified with the module's own name. We insert it under
        // user-visible ID, even though declaration itself uses the unique ID
        // as its ID.
        modified |= n->getOrCreateScope()->insert(m->scopeID(), m);

        // Also insert the module name into the global scope. We need this for
        // global look-ups that aren't associated with a specific location
        // inside the AST (like when resolving operator signatures).
        modified |= root->getOrCreateScope()->insert(m->scopeID(), m);
    }

    void operator()(declaration::Type* n) final {
        if ( n->parent()->isA<declaration::Module>() )
            modified |= n->parent()->getOrCreateScope()->insert(n);
    }

    void operator()(declaration::Field* n) final {
        if ( auto* func = n->inlineFunction() ) {
            for ( auto* x : func->ftype()->parameters() )
                modified |= n->getOrCreateScope()->insert(x);
        }

        if ( n->isStatic() )
            // Insert static member into struct's namespace.
            modified |= n->parent(3)->getOrCreateScope()->insert(n);
    }

    void operator()(expression::ListComprehension* n) final { modified |= n->getOrCreateScope()->insert(n->local()); }

    void operator()(expression::Grouping* n) final {
        if ( auto* local = n->local() )
            n->getOrCreateScope()->insert(local);
    }

    void operator()(statement::Declaration* n) final {
        modified |= n->parent()->getOrCreateScope()->insert(n->declaration());
    }

    void operator()(statement::For* n) final {
        modified |= n->getOrCreateScope()->insert(n->local());

        // Also add this to the body to avoid redefinitions
        modified |= n->body()->getOrCreateScope()->insert(n->local());
    }

    void operator()(statement::If* n) final {
        if ( auto* init = n->init() ) {
            modified |= n->getOrCreateScope()->insert(init);

            // Also add this to the true/false bodies to avoid redefinitions
            modified |= n->true_()->getOrCreateScope()->insert(init);
            if ( auto* els = n->false_() )
                modified |= els->getOrCreateScope()->insert(init);
        }
    }

    void operator()(statement::Switch* n) final {
        modified |= n->getOrCreateScope()->insert(n->condition());

        // Also add this to each case body to avoid redefinitions
        for ( auto* case_ : n->cases() )
            modified |= case_->body()->getOrCreateScope()->insert(n->condition());
    }

    void operator()(statement::try_::Catch* n) final {
        if ( auto* x = n->parameter() )
            modified |= n->getOrCreateScope()->insert(x);
    }

    void operator()(statement::While* n) final {
        if ( auto* init = n->init() ) {
            modified |= n->getOrCreateScope()->insert(init);

            // Also add this to the body and else condition to avoid redefinitions
            modified |= n->body()->getOrCreateScope()->insert(init);
            if ( auto* els = n->else_() )
                modified |= els->getOrCreateScope()->insert(init);
        }
    }

    void operator()(type::bitfield::BitRange* n) final {
        if ( auto* d = n->dd() )
            modified |= n->scope()->insert(d);
    }

    void operator()(type::Enum* n) final {
        if ( ! n->parent(2)->isA<declaration::Type>() )
            return;

        if ( ! n->typeID() )
            return;

        for ( const auto& d : n->labelDeclarations() )
            modified |= n->parent(2)->getOrCreateScope()->insert(d);
    }

    void operator()(type::Struct* n) final {
        for ( auto* x : n->parameters() )
            modified |= n->getOrCreateScope()->insert(x);

        if ( n->typeID() )
            // We need to associate the type ID with the `self` declaration,
            // so wait for that to have been set by the resolver.
            modified |= n->getOrCreateScope()->insert(n->self());
    }
};

} // anonymous namespace

bool detail::scope_builder::build(Builder* builder, Node* node) {
    util::timing::Collector _("hilti/compiler/ast/scope-builder");
    Visitor v(builder, node);
    ::hilti::visitor::visit(v, node);
    return v.modified;
}
