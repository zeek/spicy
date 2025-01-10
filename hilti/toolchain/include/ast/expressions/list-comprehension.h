// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/list.h>

namespace hilti::expression {

/** AST node for a vector comprehension expression. */
class ListComprehension : public Expression {
public:
    auto input() const { return child<Expression>(0); }
    auto output() const { return child<Expression>(1); }
    auto local() const { return child<declaration::LocalVariable>(2); }
    auto condition() const { return child<Expression>(3); }

    /**
     * Returns the output expression's scope. Note that the scope is shared
     * among any copies of an instance.
     */
    auto scope() const { return output()->scope(); }

    QualifiedType* type() const final { return child<QualifiedType>(4); }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 4, t); }

    static auto create(ASTContext* ctx, Expression* input, Expression* output, const ID& id, Expression* cond,
                       Meta meta = {}) {
        auto local = declaration::LocalVariable::create(ctx, id, QualifiedType::createAuto(ctx, meta), meta);
        auto list = QualifiedType::create(ctx, type::List::create(ctx, QualifiedType::createAuto(ctx, meta), meta),
                                          Constness::Const);
        return ctx->make<ListComprehension>(ctx, {input, output, local, cond, list}, std::move(meta));
    }

protected:
    ListComprehension(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::ListComprehension, Expression, final);
};

} // namespace hilti::expression
