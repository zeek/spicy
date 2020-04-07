// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <list>
#include <utility>

#include <hilti/ast/node.h>
#include <hilti/ast/type.h>
#include <hilti/base/type_erase.h>

namespace hilti {

namespace trait {
/** Trait for classes implementing the `Expression` interface. */
class isExpression : public isNode {};
} // namespace trait

namespace expression {
namespace detail {
#include <hilti/autogen/__expression.h>

/** Creates an AST node representing a `Expression`. */
inline Node to_node(Expression t) { return Node(std::move(t)); }

/** Renders an expression as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, Expression e) { return out << to_node(std::move(e)); }

inline bool operator==(const Expression& x, const Expression& y) {
    if ( &x == &y )
        return true;

    assert(x.isEqual(y) == y.isEqual(x)); // Expected to be symmetric.
    return x.isEqual(y);
}

inline bool operator!=(const Expression& e1, const Expression& e2) { return ! (e1 == e2); }

} // namespace detail

} // namespace expression

using Expression = expression::detail::Expression;
using expression::detail::to_node;

/** Constructs an AST node from any class implementing the `Expression` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isExpression, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Expression(std::move(t)));
}

} // namespace hilti
