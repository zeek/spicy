// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

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

namespace type {
namespace unit {
namespace detail {

#include <spicy/autogen/__unit-item.h>

/** Creates an AST node representing a `Item`. */
inline Node to_node(Item i) { return Node(std::move(i)); }

/** Renders a unit item as Spicy source code. */
inline std::ostream& operator<<(std::ostream& out, Item d) { return out << to_node(std::move(d)); }

} // namespace detail

using Item = detail::Item;
using detail::to_node;

namespace item {
/** Constructs an AST node from any class implementing the `Item` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isUnitItem, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Item(std::move(t)));
}

} // namespace item
} // namespace unit
} // namespace type
} // namespace spicy

inline bool operator==(const spicy::type::unit::Item& x, const spicy::type::unit::Item& y) {
    if ( &x == &y )
        return true;

    assert(x.isEqual(y) == y.isEqual(x)); // Expected to be symmetric.
    return x.isEqual(y);
}

// TODO(robin): Not clear why we need this. Without it, vector comparisions dont'
// seem to find the eleement comparision operator.
inline bool operator==(const std::vector<spicy::type::unit::Item>& t1, const std::vector<spicy::type::unit::Item>& t2) {
    if ( &t1 == &t2 )
        return true;

    if ( t1.size() != t2.size() )
        return false;

    for ( auto i = std::make_pair(t1.cbegin(), t2.cbegin()); i.first != t1.end() && i.second != t2.end();
          ++i.first, ++i.second )
        if ( ! (*i.first == *i.second) )
            return false;

    return true;
}

inline bool operator!=(const spicy::type::unit::Item& d1, const spicy::type::unit::Item& d2) { return ! (d1 == d2); }

inline bool operator!=(const std::vector<spicy::type::unit::Item>& t1, const std::vector<spicy::type::unit::Item>& t2) {
    return ! (t1 == t2);
}
