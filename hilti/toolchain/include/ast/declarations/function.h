// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/node-range.h>
#include <hilti/ast/operator-registry.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/type.h>

namespace hilti::declaration {

/** AST node for a function declaration. */
class Function : public Declaration {
public:
    ~Function() override {}

    auto function() const { return child<::hilti::Function>(0); }

    /** Returns an operator corresponding to a call to the function that the declaration corresponds to. */
    const auto& operator_() const { return _operator; }

    auto linkedDeclarationIndex() const { return _linked_declaration_index; }
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

    std::string displayName() const final { return "function"; }

    node::Properties properties() const final;

    static std::shared_ptr<Function> create(ASTContext* ctx, const FunctionPtr& function,
                                            declaration::Linkage linkage = Linkage::Private, const Meta& meta = {}) {
        return std::shared_ptr<Function>(new Function(ctx, {function}, function->id(), linkage, meta));
    }

protected:
    Function(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, std::move(children), std::move(id), linkage, std::move(meta)) {}

    HILTI_NODE(hilti, Function)

private:
    const Operator* _operator = nullptr;

    ast::DeclarationIndex _linked_declaration_index;
    ast::DeclarationIndex _linked_prototype_index;
};

} // namespace hilti::declaration
