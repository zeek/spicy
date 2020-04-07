// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/types/optional.h>

namespace hilti {
namespace ctor {

/** AST node for a constructor for an optional value. */
class Optional : public NodeBase, public hilti::trait::isCtor {
public:
    /** Constructs a set value. */
    Optional(Expression e, Meta m = Meta()) : NodeBase({std::move(e)}, std::move(m)) {}

    /** Constructs an unset value of type `t`. */
    Optional(Type t, Meta m = Meta()) : NodeBase({std::move(t)}, std::move(m)) {}

    std::optional<Expression> value() const { return childs()[0].tryAs<Expression>(); }

    Type dereferencedType() const {
        if ( auto x = childs()[0].tryAs<Expression>() )
            return x->type();

        return type::effectiveType(child<Type>(0));
    }

    bool operator==(const Optional& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    Type type() const { return type::Optional(dereferencedType(), meta()); }

    /** Implements `Ctor` interface. */
    bool isConstant() const {
        if ( auto e = value() )
            return e->isConstant();

        return true;
    }

    /** Implements `Ctor` interface. */
    bool isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }

    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace ctor
} // namespace hilti
