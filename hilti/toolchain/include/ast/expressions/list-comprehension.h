// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/list.h>
#include <hilti/ast/types/vector.h>

namespace hilti {
namespace expression {

/** AST node for a vector comprehension expression. */
class ListComprehension : public NodeBase, public trait::isExpression {
public:
    ListComprehension(Expression input, Expression output, ID id, std::optional<Expression> cond, Meta m = Meta())
        : NodeBase(nodes(std::move(input), std::move(output),
                         declaration::LocalVariable(std::move(id), type::auto_, true, id.meta()), std::move(cond),
                         type::List(type::auto_, m)),
                   std::move(m)) {}

    const auto& input() const { return child<Expression>(0); }
    const auto& output() const { return child<Expression>(1); }
    const auto& local() const { return child<declaration::LocalVariable>(2); }
    auto localRef() const { return NodeRef(childs()[2]); }
    auto condition() const { return childs()[3].tryAs<Expression>(); }

    /**
     * Returns the output expressions's scope. Note that the scope is shared
     * among any copies of an instance.
     */
    IntrusivePtr<Scope> scope() const { return childs()[1].scope(); }

    void setLocalType(Type t) { childs()[2].as<declaration::LocalVariable>().setType(std::move(t)); }
    void setElementType(const Type x) { childs()[4] = type::List(std::move(x)); }

    bool operator==(const ListComprehension& other) const {
        return input() == other.input() && output() == other.output() && local() == other.local() &&
               condition() == other.condition();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const Type& type() const { return childs()[4].as<Type>(); }

    /** Implements `Expression` interface. */
    auto isConstant() const { return input().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
