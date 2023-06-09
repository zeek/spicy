// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/list-comprehension.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/unresolved-id.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>

using namespace hilti;

namespace {

struct Visitor : public visitor::PostOrder<void, Visitor> {
    explicit Visitor(std::shared_ptr<hilti::Context> ctx, Unit* unit) : context(std::move(ctx)), unit(unit) {}

    std::shared_ptr<hilti::Context> context;
    Unit* unit;

    void operator()(const Module& m, position_t p) {
        auto scope = p.node.scope();

        // Insert module name into top-level scope.
        Declaration d = declaration::Module(NodeRef(p.node), m.meta());
        d.setCanonicalID(m.id());
        auto n = p.node.as<Module>().preserve(d);
        scope->insert(std::move(n));
    }

    void operator()(const declaration::GlobalVariable& d, position_t p) {
        if ( p.parent().isA<Module>() )
            p.parent().scope()->insert(NodeRef(p.node));
    }

    void operator()(const declaration::Type& d, position_t p) {
        if ( p.parent().isA<Module>() )
            p.parent().scope()->insert(NodeRef(p.node));
    }

    void operator()(const declaration::Constant& d, position_t p) {
        if ( p.parent().isA<Module>() )
            p.parent().scope()->insert(NodeRef(p.node));
    }

    void operator()(const declaration::Expression& d, position_t p) {
        if ( p.parent().isA<Module>() )
            p.parent().scope()->insert(NodeRef(p.node));
    }

    void operator()(const declaration::Field& f, position_t p) {
        if ( auto func = f.inlineFunction() ) {
            for ( auto&& x : func->ftype().parameterRefs() )
                p.node.scope()->insert(std::move(x));
        }

        if ( f.isStatic() )
            // Insert static member into struct's namespace. We create new
            // declarations here (rather than point to instances already
            // existing inside the AST) as that's (a) easier and (b) ok
            // because everything is checked to be fully resolved already.
            //
            p.parent(2).scope()->insert(NodeRef(p.node));
    }

    void operator()(const declaration::Function& f, position_t p) {
        if ( p.parent().isA<Module>() )
            p.parent().scope()->insert(NodeRef(p.node));

        for ( auto&& x : f.function().ftype().parameterRefs() )
            p.node.scope()->insert(std::move(x));

        if ( f.linkage() == declaration::Linkage::Struct ) {
            if ( ! f.id().namespace_() ) {
                p.node.addError("method lacks a type namespace");
                return;
            }
        }

        if ( f.linkage() == declaration::Linkage::Struct && f.parentStructType() && f.parentStructType()->selfRef() ) {
            const auto& t = *f.parentStructType();
            auto ns = f.id().namespace_();

            auto fields = t.fields(f.id().local());
            if ( fields.empty() ) {
                p.node.addError(util::fmt("type %s does not have a method '%s'", ns, f.id().local()));
                return;
            }

            bool found = false;
            for ( const auto& sf : fields ) {
                auto sft = sf.type().tryAs<type::Function>();

                if ( ! sft ) {
                    p.node.addError(util::fmt("%s is not a method", ID(ns, f.id().local())));
                    return;
                }

                if ( areEquivalent(*sft, f.function().ftype()) )
                    found = true;
            }

            if ( ! found ) {
                p.node.addError(
                    util::fmt("type %s does not have a method '%s' matching the signature", ns, f.id().local()));
                return;
            }

            p.node.scope()->insert(t.selfRef());

            for ( auto&& x : t.parameterRefs() )
                p.node.scope()->insert(NodeRef(x));
        }
    }

    void operator()(const declaration::ImportedModule& m, position_t p) {
        if ( const auto& cached = context->lookupUnit(m.id(), m.scope(), unit->extension()) ) {
            auto other = cached->unit->moduleRef();
            p.node.setScope(other->scope());
            auto n = unit->module().as<Module>().preserve(p.node);
            const_cast<Node&>(*n).setScope(other->scope());
            p.parent().scope()->insert(std::move(n));
        }
    }

    void operator()(const expression::ListComprehension& e, position_t p) { p.node.scope()->insert(e.localRef()); }

    void operator()(const statement::Declaration& d, position_t p) { p.parent().scope()->insert(d.declarationRef()); }

    void operator()(const statement::For& s, position_t p) { p.node.scope()->insert(s.localRef()); }

    void operator()(const statement::If& s, position_t p) {
        if ( s.initRef() )
            p.node.scope()->insert(s.initRef());
    }

    void operator()(const statement::Switch& s, position_t p) { p.node.scope()->insert(s.conditionRef()); }

    void operator()(const statement::try_::Catch& s, position_t p) {
        if ( auto x = s.parameterRef() )
            p.node.scope()->insert(std::move(x));
    }

    void operator()(const statement::While& s, position_t p) {
        if ( auto x = s.initRef() )
            p.node.scope()->insert(std::move(x));
    }

    void operator()(const type::Enum& m, position_t p) {
        if ( ! p.parent().isA<declaration::Type>() )
            return;

        if ( ! p.node.as<Type>().typeID() )
            // We need to associate the type ID with the declaration we're
            // creating, so wait for that to have been set by the resolver.
            return;

        for ( auto&& d : p.node.as<type::Enum>().labelDeclarationRefs() )
            p.parent().scope()->insert(std::move(d));
    }

    void operator()(const type::Struct& t, position_t p) {
        for ( auto&& x : t.parameterRefs() )
            p.parent().scope()->insert(std::move(x));

        if ( ! p.node.as<Type>().typeID() )
            // We need to associate the type ID with the declaration we're
            // creating, so wait for that to have been set by the resolver.
            return;

        if ( t.selfRef() )
            p.node.scope()->insert(t.selfRef());
    }
};

} // anonymous namespace

void hilti::detail::ast::buildScopes(const std::shared_ptr<hilti::Context>& ctx, Node* root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/ast/scope-builder");

    auto v = Visitor(ctx, unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);
}
