// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
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

    QualifiedTypePtr type() const final { return child<QualifiedType>(1); }

    node::Properties properties() const final {
        auto p = node::Properties{{"catch_exception", _catch_exception}};
        return Expression::properties() + p;
    }

    void setType(ASTContext* ctx, const QualifiedTypePtr& t) { setChild(ctx, 1, t); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, bool catch_exception, const Meta& meta = {}) {
        return std::shared_ptr<Deferred>(
            new Deferred(ctx, {expr, QualifiedType::createAuto(ctx, meta)}, catch_exception, meta));
    }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const Meta& meta = {}) {
        return create(ctx, expr, false, meta);
    }

protected:
    Deferred(ASTContext* ctx, Nodes children, bool catch_exception, Meta meta)
        : Expression(ctx, std::move(children), std::move(meta)), _catch_exception(catch_exception) {}

    HILTI_NODE(hilti, Deferred)

private:
    bool _catch_exception;
};

} // namespace hilti::expression
