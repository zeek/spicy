// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <list>
#include <utility>

#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/base/type_erase.h>

namespace hilti {

namespace trait {
/** Trait for classes implementing the `Type` interface. */
class isType : public isNode {};
} // namespace trait

namespace type {

namespace trait {
class hasDynamicType {};
class isAllocable {};
class isDereferencable {};
class isIterable {};
class isIterator {};
class isMutable {};
class isOnHeap {};
class isParameterized {};
class isReferenceType {};
class isRuntimeNonTrivial {};
class isView {};
class isViewable {};
class supportsWildcard {};
} // namespace trait

/** Additional flags to associated with types. */
enum class Flag {
    /** Set to make the type `const`. */
    Constant = (1U << 0U),

    /**
     * Marks the type as having a top-level scope that does not derive scope content
     * from other nodes above it in the AST (except for truely global IDs).
     */
    NoInheritScope = (1U << 1U),
};

/**
 * Stores a set of flags associated with a type.
 *
 * TODO: Replace with 3rd-party/enum-class/EnumClass.h
 */
class Flags {
public:
    Flags() = default;
    Flags(Flag f) : _flags(static_cast<uint64_t>(f)) {}
    Flags(const Flags&) = default;
    Flags(Flags&&) noexcept = default;
    ~Flags() = default;

    /** Returns true if a given flag has been set. */
    bool has(Flag f) const { return _flags & static_cast<uint64_t>(f); }

    /** Sets (or clear) a given flag. */
    void set(type::Flag flag, bool set = true) {
        if ( set )
            _flags |= static_cast<uint64_t>(flag);
        else
            _flags &= ~static_cast<uint64_t>(flag);
    }

    Flags operator+(Flag f) {
        auto x = Flags(*this);
        x.set(f);
        return x;
    }

    Flags operator+(const Flags& other) const {
        auto x = Flags();
        x._flags = _flags | other._flags;
        return x;
    }

    Flags& operator+=(Flag f) {
        set(f);
        return *this;
    }
    Flags& operator+=(const Flags& other) {
        _flags |= other._flags;
        return *this;
    }

    Flags operator-(const Flags& other) const {
        auto x = Flags();
        x._flags = _flags & ~other._flags;
        return x;
    }

    Flags& operator-=(Flag f) {
        set(f, false);
        return *this;
    }
    Flags& operator-=(const Flags& other) {
        _flags &= ~other._flags;
        return *this;
    }

    Flags& operator=(Flag f) {
        set(f);
        return *this;
    }
    Flags& operator=(const Flags&) = default;
    Flags& operator=(Flags&&) noexcept = default;

    bool operator==(Flags other) const { return _flags == other._flags; }

    bool operator!=(Flags other) const { return _flags != other._flags; }

private:
    uint64_t _flags = 0;
};

inline Flags operator+(Flag f1, Flag f2) { return Flags(f1) + f2; }

namespace detail {

struct State {
    std::optional<ID> id;
    std::optional<ID> cxx;
    type::Flags flags;
};

#include <hilti/autogen/__type.h>

/** Creates an AST node representing a `Type`. */
inline Node to_node(Type t) { return Node(std::move(t)); }

/** Renders a type as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, Type t) { return out << to_node(std::move(t)); }

} // namespace detail
} // namespace type

using Type = type::detail::Type;

/**
 * Base class for classes implementing the `Type` interface. This class
 * provides implementations for some interface methods shared that are shared
 * by all types.
 */
class TypeBase : public NodeBase, public hilti::trait::isType {
public:
    using NodeBase::NodeBase;

    /** Implements the `Type` interface. */
    bool hasFlag(type::Flag f) const { return _state().flags.has(f); }
    /** Implements the `Type` interface. */
    type::Flags flags() const { return _state().flags; }
    /** Implements the `Type` interface. */
    bool _isConstant() const { return _state().flags.has(type::Flag::Constant); }
    /** Implements the `Type` interface. */
    std::optional<ID> typeID() const { return _state().id; }
    /** Implements the `Type` interface. */
    std::optional<ID> cxxID() const { return _state().cxx; }
    /** Implements the `Type` interface. */
    const type::detail::State& _state() const { return _state_; }
    /** Implements the `Type` interface. */
    type::detail::State& _state() { return _state_; }

private:
    type::detail::State _state_;
};

namespace type {

/**
 * Copies an existing type, adding additional type flags.
 *
 * @param t original type
 * @param flags additional flags
 * @return new type with the additional flags set
 */
inline hilti::Type addFlags(const Type& t, const type::Flags& flags) {
    auto x = t._clone();
    x._state().flags += flags;
    return x;
}

/**
 * Copies an existing type, removing specified type flags.
 *
 * @param t original type
 * @param flags flags to remove
 * @return new type with the flags removed
 */
inline hilti::Type removeFlags(const Type& t, const type::Flags& flags) {
    auto x = t._clone();
    x._state().flags -= flags;
    return x;
}

/**
 * Copies an existing type, marking the type as one that stores a
 * constant/non-constant value. This has only an effect for mutable types.
 * Non-mutable are always considered const. The default for for mutable *
 * types is non-const.
 *
 * @param t original type
 * @param const_ boolen indicating whether the new type should be const
 * @return new type with the constness changed as requested
 */
inline hilti::Type setConstant(const Type& t, bool const_) {
    auto x = t._clone();
    x._state().flags.set(type::Flag::Constant, const_);
    return x;
}

/**
 * Copies an existing type, setting its C++ ID as emitted by the code generator.
 *
 * @param t original type
 * @param id new C++ ID
 * @return new type with the C++ ID set accordindly
 */
inline hilti::Type setCxxID(const Type& t, ID id) {
    auto x = t._clone();
    x._state().cxx = std::move(id);
    return x;
}

/**
 * Copies an existing type, setting its asssociated type ID.
 *
 * @param t original type
 * @param id new type ID
 * @return new type with associateed type ID set accordindly
 */
inline hilti::Type setTypeID(const Type& t, ID id) {
    auto x = t._clone();
    x._state().id = std::move(id);
    return x;
}

/**
 * Place-holder class used to enable overloading of type constructors when
 * creating wildcard types.
 */
class Wildcard {};

/**
 * Fully deferences a type, returning the type it ultimately refers to. For
 * most types, this will return them directly, but types with
 * `trait::hasDynamicProcess` can customize the process (e.g., a resolved
 * type ID will return the type the ID refers to. )
 */
inline Type effectiveType(Type t) { return t._hasDynamicType() ? t.effectiveType() : std::move(t); }

/**
 * Like `effectiveType`, accepts an optional type. If not set, the returned
 * type will likely remain unset.
 */
inline std::optional<Type> effectiveOptionalType(std::optional<Type> t) {
    if ( t )
        return effectiveType(*t);

    return {};
}

/** Returns true for HILTI types that can be used to instantiate variables. */
inline bool isAllocable(const Type& t) { return effectiveType(t)._isAllocable(); }

/** Returns true for HILTI types that one can iterator over. */
inline bool isDereferencable(const Type& t) { return effectiveType(t)._isDereferencable(); }

/** Returns true for HILTI types that one can iterator over. */
inline bool isIterable(const Type& t) { return effectiveType(t)._isIterable(); }

/** Returns true for HILTI types that represent iterators. */
inline bool isIterator(const Type& t) { return effectiveType(t)._isIterator(); }

/** Returns true for HILTI types that are parameterized with a set of type parameters. */
inline bool isParameterized(const Type& t) { return effectiveType(t)._isParameterized(); }

/** Returns true for HILTI types that implement a reference to another type. */
inline bool isReferenceType(const Type& t) { return effectiveType(t)._isReferenceType(); }

/** Returns true for HILTI types that can change their value. */
inline bool isMutable(const Type& t) { return effectiveType(t)._isMutable(); }

/** Returns true for HILTI types that, when compiled, correspond to non-POD C++ types. */
inline bool isRuntimeNonTrivial(const Type& t) { return effectiveType(t)._isRuntimeNonTrivial(); }

/** Returns true for HILTI types that represent iterators. */
inline bool isView(const Type& t) { return effectiveType(t)._isView(); }

/** Returns true for HILTI types that one can create a view for. */
inline bool isViewable(const Type& t) { return effectiveType(t)._isViewable(); }

/** Returns true for HILTI types that are always to be placed on the heap. */
inline bool isOnHeap(const Type& t) { return effectiveType(t)._isOnHeap(); }

/**
 * Returns true if the type is marked constant.
 *
 * \todo Note that currently we track this consistently only for mutable
 * types. Ideally, this would always return true for non-mutable types, but
 * doing so breaks some coercion code currently.
 */
inline bool isConstant(const Type& t) { return effectiveType(t).flags().has(type::Flag::Constant); }

/** Returns a `const` version of a type. */
inline auto constant(const Type& t) { return setConstant(t, true); }

/** Returns a not `const` version of a type. */
inline auto nonConstant(const Type& t) { return setConstant(t, false); }

/** Sets the constness of type *t* to that of another type *from*. */
inline auto transferConstness(const Type& t, const Type& from) { return setConstant(t, isConstant(from)); }

namespace detail {
inline bool operator==(const Type& t1, const Type& t2) {
    if ( &t1 == &t2 )
        return true;

    if ( type::isConstant(t1) != type::isConstant(t2) )
        return false;

    if ( t1.cxxID() && t2.cxxID() )
        return t1.cxxID() == t2.cxxID();

    if ( (t1.flags() - type::Flag::Constant) != (t2.flags() - type::Flag::Constant) )
        return false;

    // Type comparision is not fully symmetric, it's good enough
    // if one type believes it matches the other one.
    return t1.isEqual(t2) || t2.isEqual(t1);
}

inline bool operator!=(const Type& t1, const Type& t2) { return ! (t1 == t2); }

} // namespace detail

/**
 * Checks if a source type's constness suports promotion to a destination's
 * constness. This ignores the types itself, it just looks at constness.
 */
inline bool isConstCompatible(const Type& src, const Type& dst) {
    if ( type::isConstant(dst) )
        return true;

    return ! type::isConstant(src);
}

/** Returns true if two types are identical, ignoring for their constnesses. */
inline bool sameExceptForConstness(const Type& t1, const Type& t2) { return t1.isEqual(t2) || t2.isEqual(t1); }

} // namespace type

/** Constructs an AST node from any class implementing the `Type` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isType, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Type(std::move(t)));
}

} // namespace hilti
