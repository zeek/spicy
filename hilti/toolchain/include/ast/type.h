// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <type_traits>
#include <typeinfo>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/base/optional-ref.h>
#include <hilti/base/type_erase.h>
#include <hilti/base/util.h>
#include <hilti/base/visitor-types.h>

namespace spicy::type {
class Bitfield;
class Sink;
class Unit;
} // namespace spicy::type

namespace hilti {

namespace trait {
/** Trait for classes implementing the `Type` interface. */
class isType : public isNode {};
} // namespace trait

class Type;
class TypeBase;

namespace declaration {
class Parameter;
}

namespace type {

namespace function {
using Parameter = declaration::Parameter;
}

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

class Address;
class Any;
class Auto;
class Bool;
class Bytes;
class DocOnly;
class Enum;
class Error;
class Exception;
class Function;
class Interval;
class Library;
class List;
class Map;
class Member;
class Network;
class Null;
class OperandList;
class Optional;
class Port;
class Real;
class Real;
class RegExp;
class Result;
class Set;
class SignedInteger;
class Stream;
class String;
class StrongReference;
class Struct;
class Time;
class Tuple;
class Type_;
class Union;
class Unknown;
class UnresolvedID;
class UnsignedInteger;
class ValueReference;
class Vector;
class Void;
class WeakReference;

namespace bytes {
class Iterator;
}

namespace detail {
class IntegerBase;
}

namespace list {
class Iterator;
}

namespace map {
class Iterator;
}

namespace set {
class Iterator;
}

namespace stream {
class Iterator;
class View;
} // namespace stream

namespace vector {
class Iterator;
}

class Visitor {
public:
    using position_t = visitor::Position<Node&>;

    virtual void operator()(const hilti::TypeBase&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Address&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Any&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Auto&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Bool&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Bytes&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::DocOnly&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Enum&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Error&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Exception&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Function&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Interval&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Library&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::List&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Map&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Member&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Network&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Null&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::OperandList&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Optional&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Port&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Real&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::RegExp&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Result&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Set&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::SignedInteger&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Stream&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::String&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::StrongReference&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Struct&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Time&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Tuple&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Type_&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Union&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Unknown&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::UnresolvedID&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::UnsignedInteger&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::ValueReference&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Vector&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::Void&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::WeakReference&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::bytes::Iterator&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::detail::IntegerBase&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::list::Iterator&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::map::Iterator&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::set::Iterator&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::stream::Iterator&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::stream::View&, position_t&) { _not_visited = true; }
    virtual void operator()(const hilti::type::vector::Iterator&, position_t&) { _not_visited = true; }
    virtual void operator()(const spicy::type::Bitfield&, position_t&) { _not_visited = true; }
    virtual void operator()(const spicy::type::Sink&, position_t&) { _not_visited = true; }
    virtual void operator()(const spicy::type::Unit&, position_t&) { _not_visited = true; }

    bool did_visit() const { return ! _not_visited; }

private:
    bool _not_visited = false;
};

} // namespace type

/**
 * Base class for classes implementing the `Type` interface. This class
 * provides implementations for some interface methods shared that are shared
 * by all types.
 */
class TypeBase : public NodeBase {
public:
    using NodeBase::NodeBase;

    virtual ~TypeBase() = default;

    /** Returns the type of elements the iterator traverse. */
    virtual optional_ref<const Type> dereferencedType() const { return {}; }

    /** Returns the type of elements the container stores. */
    virtual optional_ref<const hilti::Type> elementType() const { return {}; }

    /** Returns true if the type is equivalent to another HILTI type. */
    virtual bool isEqual(const hilti::Type& other) const { return false; }

    /** Returns the type of an iterator for this type. */
    virtual optional_ref<const hilti::Type> iteratorType(bool const_) const { return {}; }

    /**
     * Returns true if all instances of the same type class can be coerced
     * into the current instance, independent of their pararameters. In HILTI
     * source code, this typically corresponds to a type `T<*>`.
     */
    virtual bool isWildcard() const { return false; }

    /** Returns any parameters the type expects. */
    virtual hilti::node::Set<type::function::Parameter> parameters() const { return {}; }

    /**
     * Returns any parameters associated with type. If a type is declared as
     * `T<A,B,C>` this returns a vector of the AST nodes for `A`, `B`, and
     * `C`.
     */
    virtual std::vector<Node> typeParameters() const { return {}; }

    /** Returns the type of an view for this type. */
    virtual optional_ref<const hilti::Type> viewType() const { return {}; }

    /** For internal use. Use ``type::isAllocable` instead. */
    virtual bool _isAllocable() const { return false; }

    /** For internal use. Use ``type::isIterator` instead. */
    virtual bool _isIterator() const { return false; }

    /** For internal use. Use ``type::isMutable` instead. */
    virtual bool _isMutable() const { return false; }

    /** For internal use. Use ``type::isParameterized` instead. */
    virtual bool _isParameterized() const { return false; }

    /** For internal use. Use ``type::isReferenceType` instead. */
    virtual bool _isReferenceType() const { return false; }

    /** For internal use. Use ``type::isResolved` instead. */
    virtual bool _isResolved(type::ResolvedState* rstate) const { return false; }

    /** For internal use. Use ``type::isRuntimeNonTrivial` instead. */
    virtual bool _isRuntimeNonTrivial() const { return false; }

    /** For internal use. Use ``type::isSortable` instead. */
    virtual bool _isSortable() const { return false; }

    /** Implements the `Node` interface. */
    virtual node::Properties properties() const { return {}; }

    virtual uintptr_t identity() const { return reinterpret_cast<uintptr_t>(this); }

    virtual const std::type_info& typeid_() const { return typeid(decltype(*this)); }

    virtual void dispatch(type::Visitor& v, type::Visitor::position_t& p) const { v(*this, p); }
};

#define HILTI_TYPE_VISITOR_IMPLEMENT                                                                                   \
    void dispatch(hilti::type::Visitor& v, hilti::type::Visitor::position_t& p) const override { v(*this, p); }


class Type : public type::detail::Type {
public:
    Type() = default;
    Type(const Type&) = default;
    Type(Type&&) = default;

    template<typename T, typename = std::enable_if_t<std::is_base_of_v<TypeBase, T>>>
    Type(const T& data) : _data_(std::make_shared<T>(data)) {}

    Type& operator=(const Type&) = default;
    Type& operator=(Type&&) = default;

    ~Type() override = default;

    std::optional<ID> resolvedID() const { return _state().resolved_id; }

    void setCxxID(ID id) { _state().cxx = std::move(id); }
    void setTypeID(ID id) { _state().id = std::move(id); }
    void addFlag(type::Flag f) { _state().flags += f; }

    bool hasFlag(type::Flag f) const { return _state().flags.has(f); }
    const type::Flags& flags() const { return _state().flags; }
    bool _isConstant() const { return _state().flags.has(type::Flag::Constant); }
    const std::optional<ID>& typeID() const { return _state().id; }
    const std::optional<ID>& cxxID() const { return _state().cxx; }
    const type::detail::State& _state() const { return _state_; }
    type::detail::State& _state() { return _state_; }

    /** Implements the `Node` interface. */
    bool pruneWalk() const { return hasFlag(type::Flag::PruneWalk); }
    node::Properties properties() const { return _data_->properties(); }
    const std::vector<hilti::Node>& children() const { return _data_->children(); }
    std::vector<hilti::Node>& children() { return _data_->children(); }
    const Meta& meta() const { return _data_->meta(); }
    void setMeta(Meta m) { return _data_->setMeta(std::move(m)); }

    uintptr_t identity() const { return _data_->identity(); }

    template<typename T, typename = std::enable_if<std::is_base_of_v<TypeBase, T>>>
    bool isA() const {
        if constexpr ( std::is_same_v<Type, T> )
            return true;

        return dynamic_cast<const T*>(&*_data_);
    }

    template<typename T, typename = std::enable_if<std::is_base_of_v<TypeBase, T>>>
    const T& as() const {
        if constexpr ( std::is_same_v<Type, T> )
            return *this;

        return *dynamic_cast<const T*>(&*_data_);
    }

    template<typename T, typename = std::enable_if<std::is_base_of_v<TypeBase, T>>>
    T& as() {
        if constexpr ( std::is_same_v<Type, T> )
            return *this;

        return *dynamic_cast<T*>(&*_data_);
    }

    template<typename T, typename = std::enable_if<std::is_base_of_v<TypeBase, T>>>
    optional_ref<const T> tryAs() const {
        if constexpr ( std::is_same_v<Type, T> )
            return *this;

        if ( auto d = dynamic_cast<const T*>(&*_data_) )
            return {*d};
        else
            return {};
    }

    auto typename_() const { return util::demangle(_data_->typeid_().name()); }

    const std::type_info& typeid_() const { return _data_->typeid_(); }

    void dispatch(type::Visitor& v, type::Visitor::position_t& p) const { _data_->dispatch(v, p); }

    Type _clone() const;

    /** Implements the `Type interface. */

    /** Returns true if the type is equivalent to another HILTI type. */
    bool isEqual(const hilti::Type& other) const { return _data_->isEqual(other); }

    /**
     * Returns any parameters associated with type. If a type is declared as
     * `T<A,B,C>` this returns a vector of the AST nodes for `A`, `B`, and
     * `C`.
     */
    std::vector<Node> typeParameters() const { return _data_->typeParameters(); }

    /**
     * Returns true if all instances of the same type class can be coerced
     * into the current instance, independent of their pararameters. In HILTI
     * source code, this typically corresponds to a type `T<*>`.
     */
    bool isWildcard() const { return _data_->isWildcard(); }

    /** Returns the type of an iterator for this type. */
    optional_ref<const hilti::Type> iteratorType(bool const_) const { return _data_->iteratorType(const_); }

    /** Returns the type of an view for this type. */
    optional_ref<const hilti::Type> viewType() const { return _data_->viewType(); }

    /** Returns the type of elements the iterator traverse. */
    optional_ref<const hilti::Type> dereferencedType() const { return _data_->dereferencedType(); }

    /** Returns the type of elements the container stores. */
    optional_ref<const hilti::Type> elementType() const { return _data_->elementType(); }

    /** Returns any parameters the type expects. */
    hilti::node::Set<type::function::Parameter> parameters() const { return _data_->parameters(); }

    /** For internal use. Use `type::isAllocable` instead. */
    bool _isAllocable() const { return _data_->_isAllocable(); }

    /** For internal use. Use `type::isSortable` instead. */
    bool _isSortable() const { return _data_->_isSortable(); }

    /** For internal use. Use `type::isIterator` instead. */
    bool _isIterator() const { return _data_->_isIterator(); }

    /** For internal use. Use `type::isParameterized` instead. */
    bool _isParameterized() const { return _data_->_isParameterized(); }
    /** For internal use. Use `type::isReferenceType` instead. */

    bool _isReferenceType() const { return _data_->_isReferenceType(); }

    /** For internal use. Use `type::isMutable` instead. */
    bool _isMutable() const { return _data_->_isMutable(); }

    /** For internal use. Use `type::isRuntimeNonTrivial` instead. */
    bool _isRuntimeNonTrivial() const { return _data_->_isRuntimeNonTrivial(); }

    /** For internal use. Use `type::isResolved` instead. */
    bool _isResolved(type::ResolvedState* rstate) const { return _data_->_isResolved(rstate); }

private:
    std::shared_ptr<TypeBase> _data_;
};

/** Creates an AST node representing a `Type`. */
inline Node to_node(Type t) { return Node(std::move(t)); }

/** Renders a type as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, Type t) { return out << to_node(std::move(t)); }

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
inline bool isIterable(const Type& t) { return t.iteratorType(true).has_value(); }

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

/** Returns true for HILTI types that one can create a view for. */
inline bool isViewable(const Type& t) { return t.viewType().has_value(); }

/** Returns true for HILTI types that may receive type arguments on instantiations. */
inline bool takesArguments(const Type& t) { return ! t.parameters().empty(); }

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

} // namespace hilti
