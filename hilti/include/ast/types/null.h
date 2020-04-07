// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/type.h>

namespace hilti {
namespace type {

/** AST node for a null type. */
class Null : public TypeBase {
public:
    Null(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Null& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace type
} // namespace hilti
