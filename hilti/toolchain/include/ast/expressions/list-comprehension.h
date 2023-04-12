// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/list.h>
#include <hilti/ast/types/vector.h>

namespace hilti::expression {

/** AST node for a vector comprehension expression. */
class ListComprehension : public NodeBase, public trait::isExpression {
public:
    ListComprehension(Expression input, Expression output, const ID& id, std::optional<Expression> cond,
                      Meta m = Meta())
        : NodeBase(nodes(std::move(input), std::move(output),
                         declaration::LocalVariable(id, type::auto_, true, id.meta()), std::move(cond),
                         type::List(type::auto_, m)),
                   std::move(m)) {}

    const auto& input() const { return child<Expression>(0); }
    const auto& output() const { return child<Expression>(1); }
    const auto& local() const { return child<declaration::LocalVariable>(2); }
    auto localRef() const { return NodeRef(children()[2]); }
    auto condition() const { return children()[3].tryAs<Expression>(); }

    /**
     * Returns the output expressions's scope. Note that the scope is shared
     * among any copies of an instance.
     */
    IntrusivePtr<Scope> scope() const { return children()[1].scope(); }

    void setLocalType(const Type& t) { children()[2].as<declaration::LocalVariable>().setType(t); }
    void setElementType(const Type& x) { children()[4] = type::List(x); }

    bool operator==(const ListComprehension& other) const {
        return input() == other.input() && output() == other.output() && local() == other.local() &&
               condition() == other.condition();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const Type& type() const { return children()[4].as<Type>(); }

    /** Implements `Expression` interface. */
    auto isConstant() const { return input().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
