// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/computed.h>
#include <hilti/ast/types/vector.h>

namespace hilti {
namespace expression {

/** AST node for a vector comprehension expression. */
class ListComprehension : public NodeBase, public trait::isExpression {
public:
    ListComprehension(Expression input, Expression output, ID id, std::optional<Expression> cond, Meta m = Meta())
        : NodeBase(nodes(std::move(input), std::move(output), std::move(id), std::move(cond)), std::move(m)) {
        _computeType();
    }

    const auto& input() const { return child<Expression>(0); }
    const auto& output() const { return child<Expression>(1); }
    const auto& id() const { return child<ID>(2); }
    auto condition() const { return childs()[3].tryReferenceAs<Expression>(); }

    /**
     * Returns the output expressions's scope. Note that the scope is shared
     * among any copies of an instance.
     */
    IntrusivePtr<Scope> scope() const { return childs()[1].scope(); }

    bool operator==(const ListComprehension& other) const {
        return input() == other.input() && output() == other.output() && id() == other.id() &&
               condition() == other.condition();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const auto& type() const { return child<Type>(4); }

    /** Implements `Expression` interface. */
    auto isConstant() const { return input().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    void _computeType() {
        auto t = type::Computed(NodeRef(childs()[1]), [](auto& n) -> Type {
            if ( auto x = n.template as<Expression>().type(); ! x.template isA<type::Unknown>() )
                return type::List(std::move(x), n.meta());
            else
                return type::unknown;
        });

        addChild(Type(std::move(t)));
    }
};

} // namespace expression
} // namespace hilti
