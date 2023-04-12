// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/node.h>
#include <hilti/ast/type.h>
#include <hilti/base/type_erase.h>

namespace hilti {

namespace trait {
/** Trait for classes implementing the `Ctor` interface. */
class isCtor : public isNode {};
} // namespace trait

namespace ctor::detail {
#include <hilti/autogen/__ctor.h>

/** Creates an AST node representing a `Ctor`. */
inline Node to_node(Ctor t) { return Node(std::move(t)); }

/** Renders a constructor as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, Ctor c) { return out << to_node(std::move(c)); }

inline bool operator==(const Ctor& x, const Ctor& y) {
    if ( &x == &y )
        return true;

    assert(x.isEqual(y) == y.isEqual(x)); // Expected to be symmetric.
    return x.isEqual(y);
}

inline bool operator!=(const Ctor& c1, const Ctor& c2) { return ! (c1 == c2); }

} // namespace ctor::detail

using Ctor = ctor::detail::Ctor;
using ctor::detail::to_node; // NOLINT(misc-unused-using-decls)

/** Constructs an AST node from any class implementing the `Ctor` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isCtor, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Ctor(std::move(t)));
}

} // namespace hilti
