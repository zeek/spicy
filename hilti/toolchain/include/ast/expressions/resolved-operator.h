// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/**
 * Base class for an AST node for an expression representing a resolved operator usage.
 *
 * @note Typically, one derives from this only by using the `__BEGIN_OPERATOR` macro.
 */
class ResolvedOperator : public Expression {
public:
    const auto& operator_() const { return *_operator; }
    auto kind() const { return _operator->kind(); }

    // ResolvedOperator interface with common implementations.
    auto operands() const { return children<Expression>(1, {}); }
    auto result() const { return child<QualifiedType>(0); }
    auto op0() const { return child<Expression>(1); }
    auto op1() const { return child<Expression>(2); }
    auto op2() const { return child<Expression>(3); }
    auto hasOp0() const { return children().size() >= 2; }
    auto hasOp1() const { return children().size() >= 3; }
    auto hasOp2() const { return children().size() >= 4; }

    void setOp0(ASTContext* ctx, Expression* e) { setChild(ctx, 1, e); }
    void setOp1(ASTContext* ctx, Expression* e) { setChild(ctx, 2, e); }
    void setOp2(ASTContext* ctx, Expression* e) { setChild(ctx, 3, e); }

    QualifiedType* type() const final { return result(); }

    std::string printSignature() const { return operator_::detail::printSignature(kind(), operands(), meta()); }

    node::Properties properties() const final {
        auto p = node::Properties{{"kind", to_string(_operator->kind())}};
        return Expression::properties() + p;
    }

    HILTI_NODE_1(expression::ResolvedOperator, Expression, override);

protected:
    ResolvedOperator(ASTContext* ctx, node::Tags node_tags, const Operator* op, QualifiedType* result,
                     const Expressions& operands, Meta meta)
        : Expression(ctx, node_tags, node::flatten(result, operands), std::move(meta)), _operator(op) {}

private:
    const Operator* _operator = nullptr;
};

} // namespace hilti::expression
