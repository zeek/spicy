// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

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
     * Returns the declaration index of a type declaration that's semantically
     * linked to this function declaration. That could for example be the
     * struct type for methods or hooks. Note that this is different from the
     * function's own declaration.
     */
    auto linkedDeclarationIndex() const { return _linked_declaration_index; }

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
