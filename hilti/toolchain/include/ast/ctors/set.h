// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/set.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace ctor {

/** AST node for a set constructor. */
class Set : public NodeBase, public hilti::trait::isCtor {
public:
    Set(const std::vector<Expression>& e, const Meta& m = Meta()) : NodeBase(nodes(node::none, e), m) {}
    Set(Type t, std::vector<Expression> e, Meta m = Meta())
        : NodeBase(nodes(std::move(t), std::move(e)), std::move(m)) {}

    auto elementType() const {
        if ( auto t = childs()[0].tryAs<Type>() )
            return type::effectiveType(*t);
        else {
            if ( childs().size() < 2 )
                return type::unknown;

            return childs()[1].as<Expression>().type();
        }
    }

    auto value() const { return childs<Expression>(1, -1); }

    bool operator==(const Set& other) const { return elementType() == other.elementType() && value() == other.value(); }

    /** Implements `Ctor` interface. */
    auto type() const { return type::Set(elementType(), meta()); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return false; }
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
