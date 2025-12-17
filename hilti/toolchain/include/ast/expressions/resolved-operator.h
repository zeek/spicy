// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <cassert>
#include <iterator>
#include <string>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/operand-list.h>

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

    /**
     * Returns the index of the given operand among the operator's operands.
     *
     * @param operand operand to look for
     * @returns index of the operand (0-2), or unset if not found
     */
    std::optional<size_t> operandIndex(const Expression* operand) const {
        const auto& ops = operands();

        if ( auto it = std::ranges::find(ops, operand); it != ops.end() )
            return std::distance(ops.begin(), it);

        return {};
    }

    void setOp0(ASTContext* ctx, Expression* e) { setChild(ctx, 1, e); }
    void setOp1(ASTContext* ctx, Expression* e) { setChild(ctx, 2, e); }
    void setOp2(ASTContext* ctx, Expression* e) { setChild(ctx, 3, e); }

    QualifiedType* type() const final { return result(); }

    std::string printSignature() const { return operator_::detail::printSignature(kind(), operands(), meta()); }

    node::Properties properties() const override {
        auto p = node::Properties{{"kind", to_string(_operator->kind())}};
        return Expression::properties() + std::move(p);
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
