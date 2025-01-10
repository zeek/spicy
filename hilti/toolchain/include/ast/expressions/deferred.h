// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/**
 * AST node for an expression for which evaluation is deferred at runtime to
 * a later point when explicitly requested by the runtime system. Optionally,
 * that later evaluation can catch any exceptions and return a corresponding
 * ``result<T>``.
 */
class Deferred : public Expression {
public:
    auto expression() const { return child<Expression>(0); }
    bool catchException() const { return _catch_exception; }

    QualifiedType* type() const final { return child<QualifiedType>(1); }

    node::Properties properties() const final {
        auto p = node::Properties{{"catch_exception", _catch_exception}};
        return Expression::properties() + std::move(p);
    }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 1, t); }

    static auto create(ASTContext* ctx, Expression* expr, bool catch_exception, const Meta& meta = {}) {
        return ctx->make<Deferred>(ctx, {expr, QualifiedType::createAuto(ctx, meta)}, catch_exception, meta);
    }

    static auto create(ASTContext* ctx, Expression* expr, const Meta& meta = {}) {
        return create(ctx, expr, false, meta);
    }

protected:
    Deferred(ASTContext* ctx, Nodes children, bool catch_exception, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)), _catch_exception(catch_exception) {}

    HILTI_NODE_1(expression::Deferred, Expression, final);

private:
    bool _catch_exception;
};

} // namespace hilti::expression
