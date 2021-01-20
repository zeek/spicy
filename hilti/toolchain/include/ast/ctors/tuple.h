// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>
#include <vector>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace ctor {

/** AST node for a tuple constructor. */
class Tuple : public NodeBase, public hilti::trait::isCtor {
public:
    Tuple(std::vector<Expression> v, Meta m = Meta()) : NodeBase(nodes(std::move(v)), std::move(m)) {}

    auto value() const { return childs<Expression>(0, -1); }

    bool operator==(const Tuple& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    Type type() const {
        auto v1 = value();
        auto v2 = std::vector<Type>{};
        bool is_unknown = false;
        std::transform(v1.begin(), v1.end(), std::back_inserter(v2), [&is_unknown](const Expression& e) {
            if ( e.type() == type::unknown )
                is_unknown = true;

            return e.type();
        });

        if ( is_unknown )
            return type::unknown;
        else
            return type::Tuple(v2, meta());
    }

    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }

    /** Implements `Ctor` interface. */
    auto isLhs() const {
        if ( value().empty() )
            return false;

        for ( const auto& e : value() ) {
            if ( ! e.isLhs() )
                return false;
        }

        return true;
    }

    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace ctor
} // namespace hilti
