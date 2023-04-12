// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>

#include <spicy/ast/hook.h>

namespace spicy {

namespace trait {
/** Trait for classes implementing the `Item` interface. */
class isUnitItem : public hilti::trait::isNode {};
} // namespace trait

namespace type::unit {
namespace detail {

#include <spicy/autogen/__unit-item.h>

/** Creates an AST node representing a `Item`. */
inline Node to_node(Item i) { return Node(std::move(i)); }

/** Renders a unit item as Spicy source code. */
inline std::ostream& operator<<(std::ostream& out, Item d) { return out << to_node(std::move(d)); }

} // namespace detail

using Item = detail::Item;

namespace item {
/** Constructs an AST node from any class implementing the `Item` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isUnitItem, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Item(std::move(t)));
}

} // namespace item
} // namespace type::unit
} // namespace spicy

namespace spicy::type::unit::detail {
inline bool operator==(const Item& x, const Item& y) {
    if ( &x == &y )
        return true;

    assert(x.isEqual(y) == y.isEqual(x)); // Expected to be symmetric.
    return x.isEqual(y);
}
} // namespace spicy::type::unit::detail

inline bool operator!=(const spicy::type::unit::Item& d1, const spicy::type::unit::Item& d2) { return ! (d1 == d2); }

inline bool operator!=(const std::vector<spicy::type::unit::Item>& t1, const std::vector<spicy::type::unit::Item>& t2) {
    return ! (t1 == t2);
}
