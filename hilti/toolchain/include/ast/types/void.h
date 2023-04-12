// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a void type. */
class Void : public TypeBase {
public:
    bool operator==(const Void& /* other */) const { return true; }

    // Type interface.
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Wrapper around constructor so that we can make it private. Don't use
     * this, use the singleton `type::void_` instead.
     */
    static Void create(Meta m = Meta()) { return Void(std::move(m)); }

private:
    Void(Meta m = Meta()) : TypeBase(std::move(m)) {}
};

/** Singleton. */
static const Type void_ = Void::create(Location("<singleton>"));
} // namespace hilti::type
