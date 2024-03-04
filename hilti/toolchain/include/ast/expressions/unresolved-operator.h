// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for an expression representing an unresolved operator usage. */
class UnresolvedOperator : public Expression {
public:
    auto kind() const { return _kind; }

    // Checks if all operands are fully unified and hence ready for type
    // comparison. Note that being unified is subtly different from being
    // resolved: Being resolved is a dynamically computed property that can be
    // checked anytime, whereas unification is computed regularly but may not
    // always fully reflect the current state.
    bool areOperandsUnified() const {
        for ( auto e : children<Expression>(1, {}) ) {
            if ( ! e->type()->type()->unification() )
                return false;
        }

        return true;
    }

    // Accelerated accessors for the first three operands, returning raw pointers.
    const Expression* op0() const { return dynamic_cast<Expression*>(children()[1].get()); }
    const Expression* op1() const { return dynamic_cast<Expression*>(children()[2].get()); }
    const Expression* op2() const { return dynamic_cast<Expression*>(children()[3].get()); }

    /** Implements interface for use with `OverloadRegistry`. */
    hilti::node::Range<Expression> operands() const { return children<Expression>(1, {}); }

    // Dummy implementations as the node will be rejected in validation anyway.
    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    std::string printSignature() const { return operator_::detail::printSignature(kind(), operands(), Meta()); }

    node::Properties properties() const final {
        auto p = node::Properties{{"kind", to_string(_kind)}};
        return Expression::properties() + p;
    }

    static auto create(ASTContext* ctx, operator_::Kind kind, Expressions operands, const Meta& meta = {}) {
        return ExpressionPtr(
            new UnresolvedOperator(ctx, node::flatten(QualifiedType::createAuto(ctx, meta), std::move(operands)), kind,
                                   meta));
    }

    static auto create(ASTContext* ctx, operator_::Kind kind, hilti::node::Range<Expression> operands,
                       const Meta& meta = {}) {
        return ExpressionPtr(
            new UnresolvedOperator(ctx, node::flatten(QualifiedType::createAuto(ctx, meta), operands), kind, meta));
    }

protected:
    UnresolvedOperator(ASTContext* ctx, Nodes children, operator_::Kind kind, Meta meta)
        : Expression(ctx, std::move(children), std::move(meta)), _kind(kind) {}

    HILTI_NODE(hilti, UnresolvedOperator)

private:
    operator_::Kind _kind;
};

} // namespace hilti::expression
