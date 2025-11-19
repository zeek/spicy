// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/function.h>
#include <hilti/ast/node-range.h>
#include <hilti/ast/operator-registry.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/type.h>

namespace hilti::declaration {

/** AST node for a function declaration. */
class Function : public Declaration {
public:
    auto function() const { return child<::hilti::Function>(0); }

    /** Returns an operator corresponding to a call to the function that the declaration corresponds to. */
    auto operator_() const { return _operator; }

    /**
     * Returns the type declaration that's semantically linked to this
     * function. For non-inline methods and hooks, the resolver sets the linked
     * declaration to the declaration of the struct type the method belongs to.
     *
     * This is a short-cut to manually querying the context for the declaration
     * with the index returned by `linkedDeclarationIndex()`.
     *
     * @param ctx AST context to use for the lookup
     * @return linked type, or nullptr if none
     */
    declaration::Type* linkedDeclaration(ASTContext* ctx) const {
        if ( _linked_declaration_index ) {
            auto* decl = ctx->lookup(_linked_declaration_index);
            return decl->as<declaration::Type>();
        }
        else
            return nullptr;
    }

    /**
     * Returns the declaration index of a type declaration that's semantically
     * linked to this function declaration. For non-inline methods and hooks,
     * the resolver sets the linked declaration to the declaration of the
     * struct type the method belongs to.
     */
    auto linkedDeclarationIndex() const { return _linked_declaration_index; }

    /**
     * Returns the function declaration that's linked to this function as its
     * prototype. This is set by the resolver when a function's prototype is
     * separate from its implementation.
     *
     * This is a short-cut to manually querying the context for the declaration
     * with the index returned by `linkedPrototypeIndex()`.
     *
     * @param ctx AST context to use for the lookup
     * @return linked function, or nullptr if none
     */
    declaration::Function* linkedPrototype(ASTContext* ctx) const {
        if ( _linked_prototype_index ) {
            auto* decl = ctx->lookup(_linked_prototype_index);
            return decl->as<declaration::Function>();
        }
        else
            return nullptr;
    }

    /**
     * Returns the index of a function declaration that's prototyping this
     * function if that's separate from the function's own declaration.
     */
    auto linkedPrototypeIndex() const { return _linked_prototype_index; }

    void setOperator(const Operator* op) { _operator = op; }

    void setLinkedDeclarationIndex(ast::DeclarationIndex index) {
        assert(index);
        _linked_declaration_index = index;
    }

    void setLinkedPrototypeIndex(ast::DeclarationIndex index) {
        assert(index);
        _linked_prototype_index = index;
    }

    /**
     * Returns the ID for the function declaration, regardless of the module which
     * it was implemented in. Only valid once the AST has been resolved.
     */
    ID functionID(ASTContext* ctx) const;

    std::string_view displayName() const final { return "function"; }

    node::Properties properties() const final;

    static Function* create(ASTContext* ctx, hilti::Function* function, declaration::Linkage linkage = Linkage::Private,
                            Meta meta = {}) {
        return ctx->make<Function>(ctx, {function}, function->id(), linkage, std::move(meta));
    }

protected:
    Function(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), linkage, std::move(meta)) {}

    HILTI_NODE_1(declaration::Function, Declaration, final);

private:
    const Operator* _operator = nullptr;

    ast::DeclarationIndex _linked_declaration_index;
    ast::DeclarationIndex _linked_prototype_index;
};

} // namespace hilti::declaration
