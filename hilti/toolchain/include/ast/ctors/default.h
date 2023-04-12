// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::ctor {

/** AST node for a constructor for a type's default value. */
class Default : public NodeBase, public hilti::trait::isCtor {
public:
    /** Constructs a default value of type `t`. */
    Default(Type t, Meta m = Meta()) : NodeBase({std::move(t)}, std::move(m)) {}

    /**
     * Constructs a default value of type `t`, passing specified arguments to
     * types with parameters.
     */
    Default(Type t, std::vector<Expression> type_args, Meta m = Meta())
        : NodeBase(nodes(std::move(t), std::move(type_args)), std::move(m)) {}

    auto typeArguments() const { return children<hilti::Expression>(1, -1); }

    void setTypeArguments(std::vector<hilti::Expression> args) {
        auto& c = children();
        c.erase(c.begin() + 1, c.end());
        for ( auto&& a : args )
            c.emplace_back(std::move(a));
    }

    bool operator==(const Default& other) const { return type() == other.type(); }

    /** Implements `Ctor` interface. */
    const Type& type() const { return child<Type>(0); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    bool isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::ctor
