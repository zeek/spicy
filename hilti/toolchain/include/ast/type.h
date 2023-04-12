// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <unordered_set>
#include <utility>

#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/base/type_erase.h>
#include <hilti/base/util.h>

namespace hilti {

namespace trait {
/** Trait for classes implementing the `Type` interface. */
class isType : public isNode {};
} // namespace trait

class Type;

namespace declaration {
class Parameter;
}

namespace type {

namespace function {
using Parameter = declaration::Parameter;
}

namespace trait {
class isAllocable {};
class isSortable {};
class isDereferenceable {};
class isIterable {};
class isIterator {};
class isMutable {};
class isParameterized {};
class isReferenceType {};
class isRuntimeNonTrivial {};
class isView {};
class isViewable {};
class supportsWildcard {};
class takesArguments {};
} // namespace trait

using ResolvedState = std::unordered_set<uintptr_t>;

/** Additional flags to associated with types. */
enum class Flag {
    /** Set to make the type `const`. */
    Constant = (1U << 0U),

    /** Set to make the type `non-const`. */
    NonConstant = (1U << 1U),

    /**
     * Marks the type as having a top-level scope that does not derive scope content
     * from other nodes above it in the AST (except for truly global IDs).
     */
    NoInheritScope = (1U << 2U),

    /** When walking over an AST, skip this node's children. This allows to
     * break cycles. */
    PruneWalk = (1U << 3U),
};

/**
 * Stores a set of flags associated with a type.
 *
 * TODO: Replace with 3rd-party/ArticleEnumClass-v2/EnumClass.h
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
    std::optional<ID> resolved_id;
    type::Flags flags;
};

#include <hilti/autogen/__type.h>
} // namespace detail

} // namespace type

class Type : public type::detail::Type {
public:
    using type::detail::Type::Type;

    std::optional<ID> resolvedID() const { return _state().resolved_id; }

    void setCxxID(ID id) {
        // We always normalize cxx IDs so they refer to fully qualified names.
        if ( ! util::startsWith(id, "::") )
            _state().cxx = util::fmt("::%s", id);
        else
            _state().cxx = std::move(id);
    }

    void setTypeID(ID id) { _state().id = std::move(id); }
    void addFlag(type::Flag f) { _state().flags += f; }

    /** Implements the `Type` interface. */
    bool hasFlag(type::Flag f) const { return _state().flags.has(f); }
    /** Implements the `Type` interface. */
    const type::Flags& flags() const { return _state().flags; }
    /** Implements the `Type` interface. */
    bool _isConstant() const { return _state().flags.has(type::Flag::Constant); }
    /** Implements the `Type` interface. */
    const std::optional<ID>& typeID() const { return _state().id; }
    /** Implements the `Type` interface. */
    const std::optional<ID>& cxxID() const { return _state().cxx; }
    /** Implements the `Type` interface. */
    const type::detail::State& _state() const { return _state_; }
    /** Implements the `Type` interface. */
    type::detail::State& _state() { return _state_; }
    /** Implements the `Node` interface. */
    bool pruneWalk() const { return hasFlag(type::Flag::PruneWalk); }
};

/** Creates an AST node representing a `Type`. */
inline Node to_node(Type t) { return Node(std::move(t)); }

/** Renders a type as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, Type t) { return out << to_node(std::move(t)); }

/**
 * Base class for classes implementing the `Type` interface. This class
 * provides implementations for some interface methods shared that are shared
 * by all types.
 */
class TypeBase : public NodeBase, public hilti::trait::isType {
public:
    using NodeBase::NodeBase;
};

namespace type {
namespace detail {
extern void applyPruneWalk(hilti::Type& t);
} // namespace detail

inline Type pruneWalk(Type t) {
    detail::applyPruneWalk(t);
    return t;
}

/**
 * Copies an existing type, adding additional type flags.
 *
 * @param t original type
 * @param flags additional flags
 * @return new type with the additional flags set
 */
inline hilti::Type addFlags(const Type& t, const type::Flags& flags) {
    auto x = Type(t);
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
    auto x = Type(t);
    x._state().flags -= flags;
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
    auto x = Type(t);
    x._state().cxx = std::move(id);
    return x;
}

/**
 * Copies an existing type, setting its associated type ID.
 *
 * @param t original type
 * @param id new type ID
 * @return new type with associateed type ID set accordindly
 */
inline hilti::Type setTypeID(const Type& t, ID id) {
    auto x = Type(t);
    x._state().id = std::move(id);
    return x;
}

/**
 * Place-holder class used to enable overloading of type constructors when
 * creating wildcard types.
 */
class Wildcard {};

/** Returns true for HILTI types that can be used to instantiate variables. */
inline bool isAllocable(const Type& t) { return t._isAllocable(); }

/** Returns true for HILTI types that can be compared for ordering at runtime. */
inline bool isSortable(const Type& t) { return t._isSortable(); }

/** Returns true for HILTI types that one can iterator over. */
inline bool isDereferenceable(const Type& t) { return t._isDereferenceable(); }

/** Returns true for HILTI types that one can iterator over. */
inline bool isIterable(const Type& t) { return t._isIterable(); }

/** Returns true for HILTI types that represent iterators. */
inline bool isIterator(const Type& t) { return t._isIterator(); }

/** Returns true for HILTI types that are parameterized with a set of type parameters. */
inline bool isParameterized(const Type& t) { return t._isParameterized(); }

/** Returns true for HILTI types that implement a reference to another type. */
inline bool isReferenceType(const Type& t) { return t._isReferenceType(); }

/** Returns true for HILTI types that can change their value. */
inline bool isMutable(const Type& t) { return t._isMutable(); }

/** Returns true for HILTI types that, when compiled, correspond to non-POD C++ types. */
inline bool isRuntimeNonTrivial(const Type& t) { return t._isRuntimeNonTrivial(); }

/** Returns true for HILTI types that represent iterators. */
inline bool isView(const Type& t) { return t._isView(); }

/** Returns true for HILTI types that one can create a view for. */
inline bool isViewable(const Type& t) { return t._isViewable(); }

/** Returns true for HILTI types that may receive type arguments on instantiations. */
inline bool takesArguments(const Type& t) { return t._takesArguments(); }

/**
 * Returns true if the type is marked constant.
 *
 * \todo Note that currently we track this consistently only for mutable
 * types. Ideally, this would always return true for non-mutable types, but
 * doing so breaks some coercion code currently.
 */
inline bool isConstant(const Type& t) {
    return t.flags().has(type::Flag::Constant) || (! isMutable(t) && ! t.flags().has(type::Flag::NonConstant));
}

/** Returns a `const` version of a type. */
inline auto constant(Type t) {
    t._state().flags -= type::Flag::NonConstant;
    t._state().flags += type::Flag::Constant;
    return t;
}

/**
 * Returns a not `const` version of a type. If `force` is true, then even
 * immutable types are marked as non-const. This is usually not what one wants.
 */
inline auto nonConstant(Type t, bool force = false) {
    t._state().flags -= type::Flag::Constant;

    if ( force )
        t._state().flags += type::Flag::NonConstant;

    return t;
}

namespace detail {
// Internal backends for the `isResolved()`.
extern bool isResolved(const hilti::Type& t, ResolvedState* rstate);

inline bool isResolved(const std::optional<hilti::Type>& t, ResolvedState* rstate) {
    return t.has_value() ? isResolved(*t, rstate) : true;
}

inline bool isResolved(const std::optional<const hilti::Type>& t, ResolvedState* rstate) {
    return t.has_value() ? isResolved(*t, rstate) : true;
}
} // namespace detail

/** Returns true if the type has been fully resolved, including all sub-types it may include. */
extern bool isResolved(const Type& t);

/** Returns true if the type has been fully resolved, including all sub-types it may include. */
inline bool isResolved(const std::optional<Type>& t) { return t.has_value() ? isResolved(*t) : true; }

/** Returns true if the type has been fully resolved, including all sub-types it may include. */
inline bool isResolved(const std::optional<const Type>& t) { return t.has_value() ? isResolved(*t) : true; }

/** Returns true if two types are identical, ignoring for their constnesses. */
inline bool sameExceptForConstness(const Type& t1, const Type& t2) {
    if ( &t1 == &t2 )
        return true;

    if ( t1.typeID() && t2.typeID() )
        return *t1.typeID() == *t2.typeID();

    if ( t1.cxxID() && t2.cxxID() )
        return *t1.cxxID() == *t2.cxxID();

    return t1.isEqual(t2) || t2.isEqual(t1);
}

} // namespace type

inline bool operator==(const Type& t1, const Type& t2) {
    if ( &t1 == &t2 )
        return true;

    if ( type::isMutable(t1) || type::isMutable(t2) ) {
        if ( type::isConstant(t1) && ! type::isConstant(t2) )
            return false;

        if ( type::isConstant(t2) && ! type::isConstant(t1) )
            return false;
    }

    if ( t1.typeID() && t2.typeID() )
        return *t1.typeID() == *t2.typeID();

    if ( t1.cxxID() && t2.cxxID() )
        return *t1.cxxID() == *t2.cxxID();

    // Type comparison is not fully symmetric, it's good enough
    // if one type believes it matches the other one.
    return t1.isEqual(t2) || t2.isEqual(t1);
}

inline bool operator!=(const Type& t1, const Type& t2) { return ! (t1 == t2); }

/** Constructs an AST node from any class implementing the `Type` interface. */
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isType, T>::value>* = nullptr>
inline Node to_node(T t) {
    return Node(Type(std::move(t)));
}

} // namespace hilti
