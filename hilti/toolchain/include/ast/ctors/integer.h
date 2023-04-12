// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/integer.h>

namespace hilti::ctor {

namespace detail {

// CHECK: IntegerBase = isCtor
/** Base class for AST nodes for both signed and unsigned integer constructors. */
template<typename T, typename S>
class IntegerBase : public NodeBase, public hilti::trait::isCtor {
public:
    IntegerBase(T v, int w, const Meta& m = Meta()) : NodeBase(nodes(S(w, m)), m), _value(v), _width(w) {}

    auto value() const { return _value; }
    auto width() const { return _width; }

    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    const auto& type() const { return child<Type>(0); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"value", _value}, {"width", _width}}; }

private:
    T _value;
    int _width;
};

} // namespace detail

/** AST node for a signed integer constructor. */
class SignedInteger : public detail::IntegerBase<int64_t, type::SignedInteger> {
public:
    using detail::IntegerBase<int64_t, type::SignedInteger>::IntegerBase;

    bool operator==(const SignedInteger& other) const { return value() == other.value() && width() == other.width(); }

    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
};

/** AST node for a unsigned integer constructor. */
class UnsignedInteger : public detail::IntegerBase<uint64_t, type::UnsignedInteger> {
public:
    using detail::IntegerBase<uint64_t, type::UnsignedInteger>::IntegerBase;

    bool operator==(const UnsignedInteger& other) const { return value() == other.value() && width() == other.width(); }

    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
};

} // namespace hilti::ctor
