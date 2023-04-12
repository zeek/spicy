// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/node.h>
#include <hilti/base/type_erase.h>

namespace hilti {

namespace trait {
/** Trait for classes implementing the `Statement` interface. */
class isStatement : public isNode {};
} // namespace trait

namespace statement::detail {
#include <hilti/autogen/__statement.h>

/** Creates an AST node representing a `Statement`. */
inline Node to_node(Statement t) { return Node(std::move(t)); }

/** Renders a statement as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, Statement s) { return out << to_node(std::move(s)); }

inline bool operator==(const Statement& x, const Statement& y) {
    if ( &x == &y )
        return true;

    assert(x.isEqual(y) == y.isEqual(x)); // Expected to be symmetric.
    return x.isEqual(y);
}

inline bool operator!=(const Statement& s1, const Statement& s2) { return ! (s1 == s2); }

} // namespace statement::detail

using Statement = statement::detail::Statement;

/** Constructs an AST node from any class implementing the `Statement` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isStatement, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Statement(std::move(t)));
}

} // namespace hilti
