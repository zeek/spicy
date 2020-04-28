// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace expression {

/** AST node for an expression representing an unresolved operator usage. */
class UnresolvedOperator : public NodeBase, public trait::isExpression {
public:
    UnresolvedOperator(operator_::Kind op, std::vector<Expression> operands, Meta meta = Meta())
        : NodeBase(nodes(std::move(operands)), std::move(meta)), _kind(op) {}

    auto kind() const { return _kind; }

    /** Implements interfave for use with `OverloadRegistry`. */
    auto operands() const { return childs<Expression>(0, -1); }

    bool operator==(const UnresolvedOperator& other) const {
        return kind() == other.kind() && operands() == other.operands();
    }

    /** Implements `Expression` interface. */

    // Dummy implementations as the node will be rejected in validation anyway.
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return false; }
    /** Implements `Expression` interface. */
    auto type() const { return type::unknown; }
    /** Implements `Expression` interface. */
    auto isConstant() const { return false; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"kind", to_string(_kind)}}; }

private:
    operator_::Kind _kind;
};

} // namespace expression
} // namespace hilti
