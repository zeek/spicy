// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti {
namespace ctor {

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

    auto typeArguments() const { return childs<hilti::Expression>(1, -1); }

    bool operator==(const Default& other) const { return type() == other.type(); }

    /** Implements `Ctor` interface. */
    Type type() const { return type::effectiveType(child<Type>(0)); }
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

    /**
     * Returns a new local default constructor with the type argument expressions replaced.
     *
     * @param d original declaration
     * @param i new init expresssion
     * @return new declaration that's equal to original one but with the init expression replaced
     */
    static Ctor setTypeArguments(const Default& d, std::vector<hilti::Expression> args) {
        auto x = Ctor(d)._clone().as<Default>();
        x.childs() = x.childs<Node>(0, 1);
        for ( auto&& a : args )
            x.childs().emplace_back(std::move(a));

        return std::move(x);
    }
};

} // namespace ctor
} // namespace hilti
