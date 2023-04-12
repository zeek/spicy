// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>

namespace hilti::type {

namespace detail {

// CHECK: IntegerBase = TypeBase
/** Base class for an AST node representing an integer type. */
class IntegerBase : public TypeBase, trait::isAllocable, trait::isParameterized, trait::isSortable {
public:
    IntegerBase(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {}
    IntegerBase(int width, Meta m = Meta()) : TypeBase(std::move(m)), _width(width) {}
    IntegerBase(Meta m = Meta()) : TypeBase(std::move(m)) {}

    auto width() const { return _width; }

    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"width", _width}}; }

private:
    bool _wildcard = false;
    int _width = 0;
};

} // namespace detail

/** AST node for a signed integer type. */
class SignedInteger : public detail::IntegerBase {
public:
    using detail::IntegerBase::IntegerBase;

    bool operator==(const SignedInteger& other) const { return width() == other.width(); }

    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const;

    /** Implements the `Node` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
};

/** AST node for an unsigned integer type. */
class UnsignedInteger : public detail::IntegerBase {
public:
    using detail::IntegerBase::IntegerBase;

    bool operator==(const UnsignedInteger& other) const { return width() == other.width(); }

    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const;

    /** Implements the `Node` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
};

} // namespace hilti::type
