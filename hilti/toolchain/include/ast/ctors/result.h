// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/error.h>
#include <hilti/ast/types/result.h>

namespace hilti::ctor {

/** AST node for a constructor for a result value. */
class Result : public NodeBase, public hilti::trait::isCtor {
public:
    Result(Expression v, Meta m = Meta()) : NodeBase(nodes(type::Result(type::auto_), std::move(v)), std::move(m)) {}

    hilti::optional_ref<const Expression> value() const {
        const auto& e = child<Expression>(1);

        if ( e.type() != type::Error() )
            return e;

        return {};
    }

    hilti::optional_ref<const Expression> error() const {
        const auto& e = child<Expression>(1);

        if ( e.type() == type::Error() )
            return e;

        return {};
    }

    const Type& dereferencedType() const { return children()[0].as<type::Result>().dereferencedType(); }

    void setDereferencedType(Type x) { children()[0] = type::Result(std::move(x)); }

    /** Implements `Ctor` interface. */
    const auto& type() const { return child<Type>(0); }

    /** Implements `Ctor` interface. */
    bool isConstant() const {
        if ( auto v = value() )
            return v->isConstant();

        return true;
    }

    bool operator==(const Result& other) const { return value() == other.value() && error() == other.error(); }

    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }

    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::ctor
