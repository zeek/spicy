// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/type.h>

namespace hilti {
namespace type {

/** AST node for an "any" type. */
class Any : public TypeBase {
public:
    Any(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Any& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace type
} // namespace hilti
