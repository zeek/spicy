// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/optional.h>

namespace hilti {
namespace ctor {

/** AST node for a constructor for an optional value. */
class Optional : public NodeBase, public hilti::trait::isCtor {
public:
    /** Constructs a set value. */
    Optional(Expression e, Meta m = Meta()) : NodeBase(nodes(type::Optional(type::auto_), e), m) {}

    /** Constructs an unset value of type `t`. */
    Optional(Type t, Meta m = Meta()) : NodeBase(nodes(type::Optional(std::move(t), m), node::none), m) {}

    const Type& dereferencedType() const { return childs()[0].as<type::Optional>().dereferencedType(); }
    hilti::optional_ref<const Expression> value() const { return childs()[1].tryAs<Expression>(); }

    void setDereferencedType(Type x) { childs()[0] = type::Optional(std::move(x)); }

    bool operator==(const Optional& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    const auto& type() const { return child<Type>(0); }

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
