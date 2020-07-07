// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/error.h>
#include <hilti/ast/types/result.h>

namespace hilti {
namespace ctor {

/** AST node for a constructor for a result value. */
class Result : public NodeBase, public hilti::trait::isCtor {
public:
    Result(Expression v, Meta m = Meta()) : NodeBase({std::move(v)}, std::move(m)) {}

    std::optional<Expression> value() const {
        auto e = child<Expression>(0);

        if ( e.type() != type::Error() )
            return std::move(e);

        return {};
    }

    std::optional<Expression> error() const {
        auto e = child<Expression>(0);

        if ( e.type() == type::Error() )
            return std::move(e);

        return {};
    }

    std::optional<Type> dereferencedType() const {
        if ( auto x = value() )
            return x->type();

        return {};
    }

    bool operator==(const Result& other) const { return value() == other.value() && error() == other.error(); }

    /** Implements `Ctor` interface. */
    Type type() const {
        if ( auto v = value() )
            return type::Result(v->type(), meta());

        return type::Result(type::Any(), meta());
    }

    /** Implements `Ctor` interface. */
    bool isConstant() const {
        if ( auto v = value() )
            return v->isConstant();

        return true;
    }

    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }

    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace ctor
} // namespace hilti
