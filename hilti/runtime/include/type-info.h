// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <hilti/rt/exception.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/types/address.h>
#include <hilti/rt/types/bool.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/map.h>
#include <hilti/rt/types/network.h>
#include <hilti/rt/types/null.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/set.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/types/vector.h>

namespace hilti::rt {

struct TypeInfo;

namespace type_info {

class Value;

namespace value {

/**
 * Helper class to provide safe traversal of HILTI values through the
 * type-info API. To initiate traversal, an instance of `Parent` is needed
 * that has its life-time tied to a strong reference encapsulating the value.
 * The instance will keep the value alive during its own lifetime, and the
 * traversal will catch if that ends prematurely.
 */
class Parent {
public:
    /** Constructor that ties existing HILTI value to instance. */
    template<typename T>
    Parent(const StrongReference<T>& value) : _handle(std::make_shared<bool>()), _value(value) {}

    /** Constructor that leaves instance initially untied. */
    Parent() : _handle(std::make_shared<bool>()) {}

    /** Tie instances to an existing HILTI value. */
    void tie(hilti::rt::StrongReferenceGeneric value) { _value = std::move(value); }

private:
    friend class type_info::Value;

    std::weak_ptr<bool> handle() const {
        if ( ! _value )
            throw InvalidValue("type-info traversal not tied to value");

        return _handle;
    }

    std::shared_ptr<bool> _handle;
    std::optional<hilti::rt::StrongReferenceGeneric> _value;
};

} // namespace value

/**
 * Class representing a HILTI value generically through a pair of (1) a raw
 * pointer referring the value's storage, and (2) type information describing
 * how to interpret the raw pointer. An instance may be in an invalid state
 * if there's no underlying value available (e.g., when dereferencing an
 * unset `optional`).
 *
 * Value instances are tied to a `Parent` instance. The value's data will
 * remain accessible only as long as the parent stays around. If that goes
 * away, dereferencing will throw an error.
 */
class Value {
public:
    /**
     * Constructor
     *
     * @param ptr raw pointer to storage of the value
     * @param ti type information describing how to interpret the pointer
     * @param parent parent controlling life time of the value
     */
    Value(const void* ptr, const TypeInfo* ti, const value::Parent& parent)
        : _ptr(ptr), _ti(ti), _parent_handle(parent._handle) {
        check();
    }

    /**
     * Constructor
     *
     * @param ptr raw pointer to storage of the value
     * @param ti type information describing how to interpret the pointer
     * @param parent parent value controlling life time of this value
     */
    Value(const void* ptr, const TypeInfo* ti, const Value& parent)
        : _ptr(ptr), _ti(ti), _parent_handle(parent._parent_handle) {
        check();
    }

    /**
     * Constructor that does not tie the value to a parent.
     *
     * @param ptr raw pointer to storage of the value
     * @param ti type information describing how to interpret the pointer
     * @param parent parent value controlling life time of this value
     */
    Value(const void* ptr, const TypeInfo* ti) : _ptr(ptr), _ti(ti) {}

    /**
     * Default constructor creating a value in invalid state.
     */
    Value() = default;

    /**
     * Returns a raw pointer to the value's storage.
     *
     * @throw `InvalidValue` if the instance is not referring to a valid
     * value.
     */
    const void* pointer() const {
        if ( ! _ptr )
            throw InvalidValue("value not set");

        check();
        return _ptr;
    }

    /** Returns the type information associated with the raw pointer. */
    const TypeInfo& type() const { return *_ti; }

    /** Returns a user-facing string representation of the value. */
    std::string to_string() const;

    /** Returns true if the instance is referring to a valid value. */
    operator bool() const { return _ptr != nullptr; }

private:
    // Throws if parent has expired.
    void check() const {
        std::weak_ptr<bool> default_;

        if ( ! _parent_handle.owner_before(default_) && ! default_.owner_before(_parent_handle) )
            // parent handle was never set
            return;

        if ( _parent_handle.expired() )
            throw InvalidValue("type info value expired");
    }

    const void* _ptr = nullptr;
    const TypeInfo* _ti = nullptr;
    std::weak_ptr<bool> _parent_handle;
};

namespace detail {

/**
 * Base class for auxiliary type information pertaining to types with atomic
 * values.
 */
template<typename T>
class AtomicType {
public:
    /** Returns the underlying value as a fully-typed reference. */
    const T& get(const Value& v) const { return *static_cast<const T*>(v.pointer()); }
};

/**
 * Base class for auxiliary type information pertaining to types that
 * contain a single element of another type.
 */
class DereferenceableType {
public:
    /**
     * Type of a function that, given the outer value, returns a pointer to
     * the contained element.
     */
    using Accessor = const void* (*)(const Value& v);

    /**
     * Constructor.
     *
     * @param vtype type of the contained elements
     * @param accessor function retrieving a pointer to the contained element
     */
    DereferenceableType(const TypeInfo* vtype, Accessor accessor) : _vtype(vtype), _accessor(accessor) {}

    /**
     * Returns the contained value.
     */
    Value value(const Value& v) const { return Value(_accessor(v), _vtype, v); }

    /**
     * Returns the type of elements, as passed into the constructor.
     */
    const TypeInfo* valueType() const { return _vtype; }

private:
    const TypeInfo* _vtype;
    const Accessor _accessor;
};

class IterableType;

namespace iterable_type {

/** * Iterator to traverse over value of a type storing a sequence of elements. */
class Iterator {
public:
    /**
     * Constructor.
     *
     * @param type type information for the value being iterated over
     * @param v the iterator's current value
     */
    Iterator(const IterableType* type, Value v);

    /**
     * Default constructor creating a iterator that matches the ``end()``
     * position.
     */
    Iterator() {}

    /** Advances the iterator forward. */
    Iterator& operator++();

    /** Advances the iterator forward. */
    Iterator operator++(int);

    /**
     * Dereferences the iterator, returning the contained value.
     *
     * @throws `InvalidIterator` if the iterator is not pointing to a value
     * (i.e., if it's the end position).
     */
    Value operator*() const;

    /**
     * Returns whether the iterator matches the end position..
     *
     * Note: The method does not support generic iterator comparisons, it
     * only works for matching against the end position as returned by the
     * default constructor.
     *
     * @param other iterator to compare against
     */
    bool operator==(const Iterator& other) const {
        // This is good enough just for comparing against end().
        return _cur.has_value() == other._cur.has_value();
    }

    /** Opposite of `operator==`, with the same restrictions. */
    bool operator!=(const Iterator& other) const { return ! (*this == other); }

private:
    const IterableType* _type = nullptr;
    Value _value;
    std::optional<hilti::rt::any> _cur;
};

/**
 * Helper class that provides a standard ``begin()``/``end`` range interface
 * to iterate over the elements of an iterable type.
 */
class Sequence {
public:
    /**
     * Constructor.
     *
     * @param type type information for the value to be iterated over
     * @param v the value to be iterated over
     */
    Sequence(const IterableType* type, Value v) : _begin(type, std::move(v)) {}

    /** Returns an iterator referring to the beginning of the iterable range. */
    Iterator begin() const { return _begin; }

    /** Returns an iterator referring to the end of iterable range. */
    Iterator end() const { return Iterator(); }

private:
    Iterator _begin;
};

} // namespace iterable_type

/**
 * Base class for auxiliary type information pertaining to types that contain
 * an iterable sequence of elements of another type.
 */
class IterableType {
public:
    /**
     * Type defining three functions that retrieve and manipulate an iterator
     * for traversing the sequence of contained elements. The functions are:
     *
     * 1. ``begin``: Given the outer value, returns an iterator of an
     * internal type that points the value's first contained element; or an
     * unset optional if the value's sequence is empty.
     *
     * 2. ``next`: Given a previously created iterator of the internal type,
     * moves the iterator forward to point to the next element; or returns a
     * unset optional if the iterator is already referring to the final
     * location.
     *
     * 3. `deref`:: Given a previously created iterator of the internal type,
     * return a pointer to the storage of the element that the iterator
     * refers to.
     *
     */
    using Accessor = std::tuple<std::optional<hilti::rt::any> (*)(const Value&),          // begin()
                                std::optional<hilti::rt::any> (*)(const hilti::rt::any&), // next()
                                const void* (*)(const hilti::rt::any&)>;                  // deref()

    /**
     * Constructor.
     *
     * @param etype type of the sequence's elements
     * @param accessor set of functions retrieving and manipulating an iterator to traverse the sequence of contained
     * elements
     */
    IterableType(const TypeInfo* etype, Accessor accessor) : _etype(etype), _accessor(std::move(accessor)) {}

    /** Returns a `Sequence` that can be iterated over to visit all the contained elements. */
    iterable_type::Sequence iterate(const Value& value) const { return iterable_type::Sequence(this, value); }

    /**
     * Returns the type of the contained elements, as passed into the
     * constructor.
     */
    const TypeInfo* dereferencedType() const { return _etype; }

private:
    friend class iterable_type::Iterator;

    const TypeInfo* _etype;
    const Accessor _accessor;
};

namespace iterable_type {

inline Iterator::Iterator(const IterableType* type, Value v) : _type(type) {
    _value = std::move(v);
    _cur = std::get<0>(_type->_accessor)(_value); // begin()
}

inline Iterator& Iterator::operator++() {
    if ( _cur.has_value() )
        _cur = std::get<1>(_type->_accessor)(*_cur); // next()

    return *this;
}

inline Iterator Iterator::operator++(int) {
    auto x = *this;

    if ( _cur.has_value() )
        _cur = std::get<1>(_type->_accessor)(*_cur); // next()

    return x;
}

inline Value Iterator::operator*() const {
    if ( ! _cur.has_value() )
        throw InvalidValue("type info iterator invalid");

    return Value(std::get<2>(_type->_accessor)(*_cur), _type->_etype, _value); // deref()
}

} // namespace iterable_type

/** Base class for auxiliary type information pertaining to types that do not carry a value. */
class ValueLessType {};

/**
 * Base class for auxiliary type information pertaining to types for
 * which we do not yet have implemented their full type information.
 */
class NotImplementedType {};

} // namespace detail

//////

/** Type information for type ``addr`. */
class Address : public detail::AtomicType<hilti::rt::Address> {};

/** Type information for type ``any`. */
class Any : public detail::ValueLessType {};

class Bitfield;

namespace bitfield {

/** Auxiliary type information for type ``bitfield`` describing one of its fields. */
class Bits {
public:
    /**
     * Constructor.
     *
     * @param name ID of the field
     * @param lower lower bit of the field
     * @param upper upper bit of the field
     * @param type type of the field
     * @param offset offset of the field inside the bitfield's storage tuple.
     */
    Bits(const char* name, unsigned int lower, unsigned int upper, const TypeInfo* type, std::ptrdiff_t offset)
        : name(name), lower(lower), upper(upper), type(type), _offset(offset) {}

    const std::string name;   /**< ID of the field, with an empty string indicating no name */
    const unsigned int lower; /**< lower bit of the field */
    const unsigned int upper; /**< upper bit of the field */
    const TypeInfo* type;     /**< type of the field */

    auto offset() const { return _offset; } // TODO: Remove

private:
    friend class type_info::Bitfield;

    const std::ptrdiff_t _offset;
};

}; // namespace bitfield

/** Auxiliary type information for type ``bitfield`. */
class Bitfield {
public:
    /**
     * Constructor
     *
     * @param labels the bitfield's fields
     */
    Bitfield(uint32_t width, std::vector<bitfield::Bits> bits, const TypeInfo* tuple_ti)
        : _width(width), _bits(std::move(bits)), _tuple_ti(tuple_ti) {}

    /**
     * Returns the bitfield's integer width in bits.
     *
     * @return the bitfield's width
     */
    auto width() const { return _width; }

    /** Returns the bitfield's fields. */
    const auto& bits() const { return _bits; }

    /**
     * Returns a vector that can be iterated over to visit all the fields.
     *
     * @param v the value referring to the bitfield to iterate over
     *
     * @return a vector of pairs ``(field, value)`` where *field* is the
     * current ``bitfield::Bit` and *value* is the field's value.
     */
    std::vector<std::pair<const bitfield::Bits&, Value>> iterate(const Value& v) const;

private:
    unsigned int _width = 0;
    const std::vector<bitfield::Bits> _bits;
    const TypeInfo* _tuple_ti = nullptr;
};

/** Type information for type ``bool`. */
class Bool : public detail::AtomicType<bool> {};

/** Type information for type ``bytes`. */
class Bytes : public detail::AtomicType<hilti::rt::Bytes> {};

/** Type information for type ``iterator<bytes>`. */
class BytesIterator : public detail::AtomicType<hilti::rt::bytes::SafeIterator> {};

namespace enum_ {

/** Auxiliary type information going with ``enum`` types, describing one label. */
struct Label {
    /**
     * Constructor.
     *
     * @param name ID of the label
     * @param value numerical value of the label
     */
    Label(std::string name, int64_t value) : name(std::move(name)), value(value) {}

    const std::string name; /**< ID of the label */
    const int64_t value;    /**< numerical value of the label */
};

} // namespace enum_

/** Auxiliary type information for type ``enum<*>`. */
class Enum {
public:
    /**
     * Constructor.
     *
     * @param labels the type's labels
     */
    Enum(std::vector<enum_::Label> labels) : _labels(std::move(labels)) {}

    /** Returns the type's labels. */
    const auto& labels() const { return _labels; }

    /**
     * Given an enum value, returns the label is represents. If the value
     * does not refer to a known label, a ``unknown-<value>`` label is
     * returned.
     */
    enum_::Label get(const Value& v) const {
        auto n = *static_cast<const int64_t*>(v.pointer());

        for ( const auto& l : _labels ) {
            if ( n == l.value )
                return l;
        }

        return enum_::Label(fmt("<unknown-%" PRId64 ">", n), n);
    }

private:
    const std::vector<enum_::Label> _labels;
};


/** Auxiliary type information for type ``error`. */
class Error : public detail::AtomicType<hilti::rt::result::Error> {};

/** Auxiliary type information for type ``exception`. */
class Exception : public detail::AtomicType<hilti::rt::Exception> {};

/**
 * Auxiliary type information for type ``function`. This type information is
 * not yet implemented, so there's no further information about the function
 * available.
 */
class Function : public detail::NotImplementedType {};

/** Auxiliary type information for type ``interval`. */
class Interval : public detail::AtomicType<hilti::rt::Interval> {};

/** Auxiliary type information for type ``__library_type`. */
class Library : public detail::AtomicType<hilti::rt::TypeInfo*> {
public:
    /**
     * Constructor.
     *
     * @param cxx_name C++-side name of the type
     */
    Library(std::string cxx_name) : cxx_name(std::move(cxx_name)) {}

    /** Returns the C++-side name of the type. */
    const auto& cxxName() const { return cxx_name; }

private:
    const std::string cxx_name;
};

class Map;

namespace map {

/** Iterator to traverse over a map's value. */
class Iterator {
public:
    /**
     * Constructor.
     *
     * @param type type information for the value being iterated over
     * @param v the iterator's current value
     */
    Iterator(const Map* type, Value v);

    /**
     * Default constructor creating an iterator that matches the ``end()``
     * position.
     */
    Iterator() {}

    /** Advances the iterator forward. */
    Iterator& operator++();

    /** Advances the iterator forward. */
    Iterator operator++(int);

    /**
     * Dereferences the iterator, returning the contained value.
     *
     * @throws `InvalidIterator` if the iterator is not pointing to a value
     * (i.e., if it's the end position).
     */
    std::pair<Value, Value> operator*() const;

    /**
     * Returns whether the iterator matches the end position..
     *
     * Note: The method does not support generic iterator comparisons, it
     * only works for matching against the end position as returned by the
     * default constructor.
     *
     * @param other iterator to compare against
     */
    bool operator==(const Iterator& other) const {
        // This is good enough just for comparing against end().
        return _cur.has_value() == other._cur.has_value();
    }

    /** Opposite of `operator==`, with the same restrictions. */
    bool operator!=(const Iterator& other) const { return ! (*this == other); }

private:
    const Map* _type = nullptr;
    Value _value;
    std::optional<hilti::rt::any> _cur;
};

/**
 * Helper class that provides a standard ``begin()``/``end`` range interface
 * to iterate over the elements of an iterable type.
 */
class Sequence {
public:
    /**
     * Constructor.
     *
     * @param type type information for the value to be iterated over
     * @param v the value to be iterated over
     */
    Sequence(const Map* type, Value v) : _begin(type, std::move(v)) {}

    /** Returns an iterator referring to the beginning of the iterable range. */
    Iterator begin() const { return _begin; }

    /** Returns an iterator referring to the end of iterable range. */
    Iterator end() const { return Iterator(); }

private:
    Iterator _begin;
};
} // namespace map

/** Auxiliary type information for type ``map`. */
class Map {
public:
    /**
     * Similar semantics as with `IterableType`, but with different type for
     * dereferenced value.
     */
    using Accessor = std::tuple<std::optional<hilti::rt::any> (*)(const Value&),                 // begin()
                                std::optional<hilti::rt::any> (*)(const hilti::rt::any&),        // next()
                                std::pair<const void*, const void*> (*)(const hilti::rt::any&)>; // deref()

    /**
     * Constructor.
     *
     * @param ktype type of the keys of the contained elements
     * @param vtype type of the values of the contained elements
     * @param accessor set of functions retrieving and manipulating an iterator to traverse the sequence of contained
     * elements
     */
    Map(const TypeInfo* ktype, const TypeInfo* vtype, Accessor accessor)
        : _ktype(ktype), _vtype(vtype), _accessor(std::move(accessor)) {}

    /** Returns a `Sequence` that can be iterated over to visit all the contained elements. */
    map::Sequence iterate(const Value& value) const { return map::Sequence(this, value); }

    /**
     * Returns the type of the key of the elements, as passed into the
     * constructor.
     */
    const TypeInfo* keyType() const { return _ktype; }

    /**
     * Returns the type of the value of the elements, as passed into the constructor.
     */
    const TypeInfo* valueType() const { return _vtype; }

    template<typename K, typename V>
    using iterator_pair =
        std::pair<typename hilti::rt::Map<K, V>::const_iterator, typename hilti::rt::Map<K, V>::const_iterator>;

    template<typename K, typename V>
    static Accessor accessor() {
        return std::make_tuple(
            [](const Value& v_) -> std::optional<hilti::rt::any> { // begin()
                auto v = static_cast<const hilti::rt::Map<K, V>*>(v_.pointer());
                if ( v->cbegin() != v->cend() )
                    return std::make_pair(v->cbegin(), v->cend());
                else
                    return std::nullopt;
            },
            [](const hilti::rt::any& i_) -> std::optional<hilti::rt::any> { // next()
                auto i = hilti::rt::any_cast<iterator_pair<K, V>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](const hilti::rt::any& i_) -> std::pair<const void*, const void*> { // deref()
                auto i = hilti::rt::any_cast<iterator_pair<K, V>>(i_);
                return std::make_pair(&(*i.first).first, &(*i.first).second);
            });
    }

private:
    friend class map::Iterator;

    const TypeInfo* _ktype;
    const TypeInfo* _vtype;
    Accessor _accessor;
};

namespace map {

inline Iterator::Iterator(const Map* type, Value v) : _type(type) {
    _value = std::move(v);
    _cur = std::get<0>(_type->_accessor)(_value); // begin()
}

inline Iterator& Iterator::operator++() {
    if ( _cur.has_value() )
        _cur = std::get<1>(_type->_accessor)(*_cur); // next()

    return *this;
}

inline Iterator Iterator::operator++(int) {
    auto x = *this;

    if ( _cur.has_value() )
        _cur = std::get<1>(_type->_accessor)(*_cur); // next()

    return x;
}

inline std::pair<Value, Value> Iterator::operator*() const {
    if ( ! _cur.has_value() )
        throw InvalidValue("type info iterator invalid");

    auto x = std::get<2>(_type->_accessor)(*_cur);
    return std::make_pair(Value(x.first, _type->_ktype, _value), Value(x.second, _type->_vtype, _value));
}

} // namespace map

/** Auxiliary type information for type ``iterator<map>`. */
class MapIterator {
public:
    /**
     * Type of a function that, given the outer value, returns a pointer to
     * the contained element.
     */
    using Accessor = std::pair<const void*, const void*> (*)(const Value& v);

    /**
     * Constructor.
     *
     * @param ktype type of the keys of the contained elements
     * @param vtype type of the values of the contained elements
     * @param accessor function retrieving a pointer to the contained element
     */
    MapIterator(const TypeInfo* ktype, const TypeInfo* vtype, Accessor accessor)
        : _ktype(ktype), _vtype(vtype), _accessor(accessor) {}

    /**
     * Returns the contained value as (key, value) pair.
     */
    std::pair<Value, Value> value(const Value& v) const {
        auto x = _accessor(v);
        return std::make_pair(Value(x.first, _ktype, v), Value(x.second, _vtype, v));
    }

    /**
     * Returns the type of the key of the elements, as passed into the
     * constructor.
     */
    const TypeInfo* keyType() const { return _ktype; }

    /**
     * Returns the type of the value of the elements, as passed into the constructor.
     */
    const TypeInfo* valueType() const { return _vtype; }

    template<typename K, typename V>
    static auto accessor() { // deref()
        return [](const Value& v) -> std::pair<const void*, const void*> {
            using iterator_type = const hilti::rt::map::Iterator<K, V>;
            const auto& x = **static_cast<iterator_type*>(v.pointer());
            return std::make_pair(&x.first, &x.second);
        };
    }

private:
    const TypeInfo* _ktype;
    const TypeInfo* _vtype;
    const Accessor _accessor;
};

/** Auxiliary type information for type ``net`. */
class Network : public detail::AtomicType<hilti::rt::Network> {};

/** Auxiliary type information for type ``null`. */
class Null : public detail::ValueLessType {};

/** Auxiliary type information for type ``optional<T>`. */
class Optional : public detail::DereferenceableType {
public:
    using detail::DereferenceableType::DereferenceableType;

    template<typename T>
    static auto accessor() { // deref()
        return [](const Value& v) -> const void* {
            auto x = static_cast<const std::optional<T>*>(v.pointer());
            return x->has_value() ? &*x : nullptr;
        };
    }
};

/** Auxiliary type information for type ``port`. */
class Port : public detail::AtomicType<hilti::rt::Port> {};

/** Auxiliary type information for type ``real`. */
class Real : public detail::AtomicType<double> {};

/** Auxiliary type information for type ``regexp`. */
class RegExp : public detail::AtomicType<hilti::rt::RegExp> {};

/** Auxiliary type information for type ``result<T>`. */
class Result : public detail::DereferenceableType {
public:
    using detail::DereferenceableType::DereferenceableType;

    template<typename T>
    static auto accessor() { // deref()
        return [](const Value& v) -> const void* {
            auto x = static_cast<const hilti::rt::Result<T>*>(v.pointer());
            return x->hasValue() ? &*x : nullptr;
        };
    }

    // TODO: Cannot get to the error currently.
};

/** Auxiliary type information for type ``set<T>`. */
class Set : public detail::IterableType {
public:
    using detail::IterableType::IterableType;

    template<typename T>
    using iterator_pair =
        std::pair<typename hilti::rt::Set<T>::const_iterator, typename hilti::rt::Set<T>::const_iterator>;

    template<typename T>
    static Accessor accessor() {
        return std::make_tuple(
            [](const Value& v_) -> std::optional<hilti::rt::any> {
                auto v = static_cast<const hilti::rt::Set<T>*>(v_.pointer());
                if ( v->begin() != v->end() )
                    return std::make_pair(v->begin(), v->end());
                else
                    return std::nullopt;
            },
            [](const hilti::rt::any& i_) -> std::optional<hilti::rt::any> {
                auto i = hilti::rt::any_cast<iterator_pair<T>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](const hilti::rt::any& i_) -> const void* {
                auto i = hilti::rt::any_cast<iterator_pair<T>>(i_);
                return &*i.first;
            });
    }
};

/** Auxiliary type information for type ``iterator<set>`. */
class SetIterator : public detail::DereferenceableType {
public:
    using detail::DereferenceableType::DereferenceableType;

    template<typename T>
    static auto accessor() { // deref()
        return [](const Value& v) -> const void* {
            return &**static_cast<const hilti::rt::set::Iterator<T>*>(v.pointer());
        };
    }
};

/** Auxiliary type information for type ``int<T>`. */
template<typename Width>
class SignedInteger : public detail::AtomicType<Width> {};

/** Auxiliary type information for type ``stream`. */
class Stream : public detail::AtomicType<hilti::rt::Stream> {};

/** Auxiliary type information for type ``iterator<stream>`. */
class StreamIterator : public detail::AtomicType<hilti::rt::stream::SafeConstIterator> {};

/** Auxiliary type information for type ``view<stream>`. */
class StreamView : public detail::AtomicType<hilti::rt::stream::View> {};

/** Auxiliary type information for type ``string`. */
class String : public detail::AtomicType<std::string> {};

/** Auxiliary type information for type ``strong_ref<T>`. */
class StrongReference : public detail::DereferenceableType {
public:
    using detail::DereferenceableType::DereferenceableType;

    template<typename T>
    static auto accessor() { // deref()
        return [](const Value& v) -> const void* {
            return static_cast<const hilti::rt::StrongReference<T>*>(v.pointer())->get();
        };
    }
};


class Struct;

namespace struct_ {

/** Auxiliary type information for type ``struct`` describing one field. */
struct Field {
    /**
     * Type of a function that, given a field value, returns a pointer to the
     * contained value.
     */
    using Accessor = const void* (*)(const Value& v);

    /**
     * Constructor.
     *
     * @param name ID of the field
     * @param type type of the field
     * @param offset offset of the field in number bytes inside the struct
     * @param accessor function returning a pointer to a fields value
     */
    Field(const char* name, const TypeInfo* type, std::ptrdiff_t offset, bool internal, bool anonymous, bool emitted,
          Accessor accessor = accessor_default)
        : name(name),
          type(type),
          offset(offset),
          accessor(accessor),
          internal(internal),
          anonymous(anonymous),
          emitted(emitted) {}

    /** Default accessor function suitable for non-optional fields. */
    static const void* accessor_default(const Value& v) { return v.pointer(); }

    /** Alternative accessor function for ``&optional`` fields. */
    template<typename T>
    static Accessor accessor_optional() {
        return [](const Value& v) -> const void* {
            auto x = static_cast<const std::optional<T>*>(v.pointer());
            if ( x->has_value() ) {
                auto& o = *x;
                return &*o;
            }
            else
                return nullptr;
        };
    }

    bool isAnonymous() const { return anonymous; }
    bool isInternal() const { return internal; }
    bool isEmitted() const { return emitted; }

    const std::string name; /**< ID of the field */
    const TypeInfo* type /**< type of the field */;

private:
    friend class type_info::Struct;

    // Internal wrapper around accessor that's used from ``Struct``.
    Value value(const Value& v) const { return Value(accessor(v), type, v); }

    const std::ptrdiff_t offset;
    const Accessor accessor;
    const bool internal;
    const bool anonymous;
    const bool emitted;
};

}; // namespace struct_

/** Auxiliary type information for type ``struct`. */
class Struct {
public:
    /**
     * Constructor
     *
     * @param fields the struct's fields
     */
    Struct(std::vector<struct_::Field> fields) : _fields(std::move(fields)) {}

    /**
     * Returns the struct's fields. This includes any fields of the original
     * HILTI-side struct, even if they have not been emitted into the compiled
     * C++ struct.
     *
     * @param include_internal include internal fields
     * */

    auto fields(bool include_internal = false) const {
        std::vector<std::reference_wrapper<const struct_::Field>> fields;
        std::ranges::copy_if(_fields, std::back_inserter(fields),
                             [=](const struct_::Field& f) { return include_internal || ! f.isInternal(); });
        return fields;
    }

    /**
     * Returns a vector that can be iterated over to visit all the fields. This
     * will skip any fields that are part of the original HILTI-side struct,
     * but have not been emitted into the compiled C++ struct.
     *
     * @param v the value referring to the struct to iterate over
     * @param include_internal include internal fields
     *
     * @return a vector of pairs ``(field, value)`` where *field* is the
     * current ``struct_::Field` and *value* is the field's value.
     */
    auto iterate(const Value& v, bool include_internal = false) const {
        std::vector<std::pair<const struct_::Field&, Value>> values;

        for ( const auto& f : fields(include_internal) ) {
            if ( ! f.get().emitted )
                continue;

            auto x = Value(static_cast<const char*>(v.pointer()) + f.get().offset, f.get().type, v);
            values.emplace_back(f.get(), f.get().value(x));
        }

        return values;
    }

private:
    const std::vector<struct_::Field> _fields;
};

/** Auxiliary type information for type ``time`. */
class Time : public detail::AtomicType<hilti::rt::Time> {};

class Tuple;

namespace tuple {

/** Auxiliary type information for type ``tuple`` describing one tuple element. */
class Element {
public:
    /**
     * Constructor.
     *
     * @param name ID of the element, with an empty string indicating no name
     * @param type type of the field
     * @param offset offset of the field inside the tuple
     */
    Element(const char* name, const TypeInfo* type, std::ptrdiff_t offset) : name(name), type(type), offset(offset) {}

    const std::string name; /**< ID of the element, with an empty string indicating no name */
    const TypeInfo* type;   /**< type of the element */

private:
    friend class type_info::Tuple;

    const std::ptrdiff_t offset;
};

}; // namespace tuple

/** Auxiliary type information for type ``tuple`. */
class Tuple {
public:
    /**
     * Constructor
     *
     * @param labels the tuple's elements
     */
    Tuple(std::vector<tuple::Element> elements) : _elements(std::move(elements)) {}

    /** Returns the tuple's elements. */
    const auto& elements() const { return _elements; }

    /**
     * Returns a vector that can be iterated over to visit all the elements.
     *
     * @param v the value referring to the tuple to iterate over
     *
     * @return a vector of pairs ``(element, value)`` where *element* is the
     * current ``tuple::Element` and *value* is the element's value.
     */
    auto iterate(const Value& v) const {
        std::vector<std::pair<const tuple::Element&, Value>> values;

        const auto* tb = static_cast<const ::hilti::rt::TupleBase*>(v.pointer());

        size_t index = 0;
        values.reserve(_elements.size());
        for ( const auto& f : _elements ) {
            if ( tb->hasValue(index++) )
                values.emplace_back(f, Value(static_cast<const char*>(v.pointer()) + f.offset, f.type, v));
            else
                values.emplace_back(f, Value()); // unset value
        }

        return values;
    }

private:
    const std::vector<tuple::Element> _elements;
};

namespace union_ {

/** Auxiliary type information for type ``union`` describing one field. */
struct Field {
    /**
     * Constructor.
     *
     * @param name ID of the field
     * @param type type of the field
     */
    Field(const char* name, const TypeInfo* type) : name(name), type(type) {}

    const std::string name; /**< ID of the field */
    const TypeInfo* type;   /**< type of the field */
};

}; // namespace union_

/** Auxiliary type information for type ``union`. */
class Union {
public:
    /**
     * Type of a function that, given a union value, returns the index of the
     * currently set field, with `npos` indicating no field being set.
     */
    using Accessor = std::size_t (*)(const Value& v);
    const size_t npos = std::variant_npos;

    /**
     * Constructor
     *
     * @param labels the union's fields
     * @param accessor accessor function returning the index of the currently set field
     */
    Union(std::vector<union_::Field> fields, Accessor accessor) : _fields(std::move(fields)), _accessor(accessor) {}

    /** Returns the union's fields. */
    const auto& fields() const { return _fields; }

    /**
     * Returns the union's current value. The value will be invalid if
     * there's no field set currently.
     */
    Value value(const Value& v) const {
        if ( auto idx = _accessor(v); idx > 0 )
            return Value(v.pointer(), _fields[idx - 1].type, v);
        else
            return Value();
    }

    template<typename T>
    static auto accessor() {
        return [](const Value& v) -> std::size_t { return static_cast<const T*>(v.pointer())->index(); };
    }

private:
    const std::vector<union_::Field> _fields;
    const Accessor _accessor;
};

/** Auxiliary type information for type ``int<T>`. */
template<typename Width>
class UnsignedInteger : public detail::AtomicType<Width> {};

/** Auxiliary type information for type ``value_ref<T>`. */
class ValueReference : public detail::DereferenceableType {
public:
    using detail::DereferenceableType::DereferenceableType;

    template<typename T>
    static auto accessor() { // deref()
        return [](const Value& v) -> const void* {
            return static_cast<const hilti::rt::ValueReference<T>*>(v.pointer())->get();
        };
    }
};

/** Auxiliary type information for type ``vector<T>`. */
class Vector : public detail::IterableType {
public:
    using detail::IterableType::IterableType;

    template<typename T, typename Allocator>
    using iterator_pair = std::pair<typename hilti::rt::Vector<T, Allocator>::const_iterator,
                                    typename hilti::rt::Vector<T, Allocator>::const_iterator>;

    template<typename T, typename Allocator = std::allocator<T>>
    static Accessor accessor() {
        return std::make_tuple(
            [](const Value& v_) -> std::optional<hilti::rt::any> { // begin()
                auto v = static_cast<const hilti::rt::Vector<T, Allocator>*>(v_.pointer());
                if ( v->begin() != v->end() )
                    return std::make_pair(v->begin(), v->end());
                else
                    return std::nullopt;
            },
            [](const hilti::rt::any& i_) -> std::optional<hilti::rt::any> { // next()
                auto i = hilti::rt::any_cast<iterator_pair<T, Allocator>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](const hilti::rt::any& i_) -> const void* { // deref()
                auto i = hilti::rt::any_cast<iterator_pair<T, Allocator>>(i_);
                return &*i.first;
            });
    }
};

/** Auxiliary type information for type ``iterator<vector>`. */
class VectorIterator : public detail::DereferenceableType {
public:
    using detail::DereferenceableType::DereferenceableType;

    template<typename T, typename Allocator = std::allocator<T>>
    static auto accessor() { // deref()
        return [](const Value& v) -> const void* {
            return &**static_cast<const hilti::rt::vector::Iterator<T, Allocator>*>(v.pointer());
        };
    }
};

/** Auxiliary type information for type ``void`. */
class Void : public detail::ValueLessType {};

/** Auxiliary type information for type ``weak_ref<T>`. */
class WeakReference : public detail::DereferenceableType {
public:
    using detail::DereferenceableType::DereferenceableType;

    template<typename T>
    static auto accessor() { // deref()
        return [](const Value& v) -> const void* {
            return static_cast<const hilti::rt::WeakReference<T>*>(v.pointer())->get();
        };
    }
};

} // namespace type_info

} // namespace hilti::rt

namespace hilti::rt {

/**
 * Top-level type information structure describing one type. There's a generic
 * part applying to all types, plus a tagged union storing additional,
 * type-specific auxiliary information. To query which union field is set users
 * should query the `tag` member.
 */
struct TypeInfo {
    std::optional<const char*> id; /**< Spicy-side ID associated with the type, if any. */
    const char* display = nullptr; /**< String rendering of the type. */

    enum Tag {
        Undefined,
        Address,
        Any,
        Bitfield,
        Bool,
        Bytes,
        BytesIterator,
        Enum,
        Error,
        Exception,
        Function,
        Interval,
        Library,
        Map,
        MapIterator,
        Network,
        Null,
        Optional,
        Port,
        Real,
        RegExp,
        Result,
        Set,
        SetIterator,
        SignedInteger_int8,
        SignedInteger_int16,
        SignedInteger_int32,
        SignedInteger_int64,
        Stream,
        StreamIterator,
        StreamView,
        String,
        StrongReference,
        Struct,
        Time,
        Tuple,
        Union,
        UnsignedInteger_uint8,
        UnsignedInteger_uint16,
        UnsignedInteger_uint32,
        UnsignedInteger_uint64,
        ValueReference,
        Vector,
        VectorIterator,
        Void,
        WeakReference
    };

    // Actual storage for the held type.
    std::unique_ptr<const char, void (*)(const char*)> _storage = {nullptr, [](const char*) {}};

    // Callback rendering a value of the type into a string. User-code should
    // use `Value::to_string()` instead of calling this directly.
    std::string (*const _to_string)(const void* const) = nullptr;

    Tag tag = Tag::Undefined; ///< Tag indicating which field of below union is set.
    union {
        type_info::Address* address;
        type_info::Any* any;
        type_info::Bitfield* bitfield;
        type_info::Bool* bool_;
        type_info::Bytes* bytes;
        type_info::BytesIterator* bytes_iterator;
        type_info::Enum* enum_;
        type_info::Error* error;
        type_info::Exception* exception;
        type_info::Function* function;
        type_info::Interval* interval;
        type_info::Library* library;
        type_info::Map* map;
        type_info::MapIterator* map_iterator;
        type_info::Network* network;
        type_info::Null* null;
        type_info::Optional* optional;
        type_info::Port* port;
        type_info::Real* real;
        type_info::RegExp* regexp;
        type_info::Result* result;
        type_info::Set* set;
        type_info::SetIterator* set_iterator;
        type_info::SignedInteger<int8_t>* signed_integer_int8;
        type_info::SignedInteger<int16_t>* signed_integer_int16;
        type_info::SignedInteger<int32_t>* signed_integer_int32;
        type_info::SignedInteger<int64_t>* signed_integer_int64;
        type_info::Stream* stream;
        type_info::StreamIterator* stream_iterator;
        type_info::StreamView* stream_view;
        type_info::String* string;
        type_info::StrongReference* strong_reference;
        type_info::Struct* struct_;
        type_info::Time* time;
        type_info::Tuple* tuple;
        type_info::Union* union_;
        type_info::UnsignedInteger<uint8_t>* unsigned_integer_uint8;
        type_info::UnsignedInteger<uint16_t>* unsigned_integer_uint16;
        type_info::UnsignedInteger<uint32_t>* unsigned_integer_uint32;
        type_info::UnsignedInteger<uint64_t>* unsigned_integer_uint64;
        type_info::ValueReference* value_reference;
        type_info::Vector* vector;
        type_info::VectorIterator* vector_iterator;
        type_info::Void* void_;
        type_info::WeakReference* weak_reference;
    };

    TypeInfo() = default;

    template<typename Type>
    TypeInfo(std::optional<const char*> _id, const char* _display, std::string (*const to_string)(const void*),
             Type* value)
        : id(_id),
          display(_display),
          _storage(reinterpret_cast<const char*>(value),
                   [](const char* p) { delete reinterpret_cast<const Type*>(p); }),
          _to_string(to_string) {
        if constexpr ( std::is_same_v<Type, type_info::Address> ) {
            tag = Address;
            address = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Any> ) {
            tag = Any;
            any = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Bitfield> ) {
            tag = Bitfield;
            bitfield = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Bool> ) {
            tag = Bool;
            bool_ = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Bytes> ) {
            tag = Bytes;
            bytes = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::BytesIterator> ) {
            tag = BytesIterator;
            bytes_iterator = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Enum> ) {
            tag = Enum;
            enum_ = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Error> ) {
            tag = Error;
            error = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Exception> ) {
            tag = Exception;
            exception = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Function> ) {
            tag = Function;
            function = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Interval> ) {
            tag = Interval;
            interval = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Library> ) {
            tag = Library;
            library = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Map> ) {
            tag = Map;
            map = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::MapIterator> ) {
            tag = MapIterator;
            map_iterator = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Network> ) {
            tag = Network;
            network = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Null> ) {
            tag = Null;
            null = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Optional> ) {
            tag = Optional;
            optional = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Port> ) {
            tag = Port;
            port = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Real> ) {
            tag = Real;
            real = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::RegExp> ) {
            tag = RegExp;
            regexp = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Result> ) {
            tag = Result;
            result = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Set> ) {
            tag = Set;
            set = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::SetIterator> ) {
            tag = SetIterator;
            set_iterator = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::SignedInteger<int8_t>> ) {
            tag = SignedInteger_int8;
            signed_integer_int8 = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::SignedInteger<int16_t>> ) {
            tag = SignedInteger_int16;
            signed_integer_int16 = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::SignedInteger<int32_t>> ) {
            tag = SignedInteger_int32;
            signed_integer_int32 = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::SignedInteger<int64_t>> ) {
            tag = SignedInteger_int64;
            signed_integer_int64 = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Stream> ) {
            tag = Stream;
            stream = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::StreamIterator> ) {
            tag = StreamIterator;
            stream_iterator = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::StreamView> ) {
            tag = StreamView;
            stream_view = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::String> ) {
            tag = String;
            string = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::StrongReference> ) {
            tag = StrongReference;
            strong_reference = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Struct> ) {
            tag = Struct;
            struct_ = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Time> ) {
            tag = Time;
            time = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Tuple> ) {
            tag = Tuple;
            tuple = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Union> ) {
            tag = Union;
            union_ = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::UnsignedInteger<uint8_t>> ) {
            tag = UnsignedInteger_uint8;
            unsigned_integer_uint8 = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::UnsignedInteger<uint16_t>> ) {
            tag = UnsignedInteger_uint16;
            unsigned_integer_uint16 = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::UnsignedInteger<uint32_t>> ) {
            tag = UnsignedInteger_uint32;
            unsigned_integer_uint32 = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::UnsignedInteger<uint64_t>> ) {
            tag = UnsignedInteger_uint64;
            unsigned_integer_uint64 = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::ValueReference> ) {
            tag = ValueReference;
            value_reference = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Vector> ) {
            tag = Vector;
            vector = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::VectorIterator> ) {
            tag = VectorIterator;
            vector_iterator = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::Void> ) {
            tag = Void;
            void_ = value;
        }
        else if constexpr ( std::is_same_v<Type, type_info::WeakReference> ) {
            tag = WeakReference;
            weak_reference = value;
        }
        else {
            throw RuntimeError("unhandled type");
        }
    }
};

inline std::ostream& operator<<(std::ostream& out, const TypeInfo& t) { return out << t.display; }
inline std::ostream& operator<<(std::ostream& out, const TypeInfo* t) { return out << t->display; }

namespace detail::adl {
inline std::string to_string(const hilti::rt::TypeInfo& ti, adl::tag /*unused*/) { return ti.display; }
inline std::string to_string(const hilti::rt::TypeInfo* ti, adl::tag /*unused*/) { return ti->display; }
} // namespace detail::adl

namespace type_info {

inline std::string Value::to_string() const {
    if ( ! _ti->_to_string )
        // This should only not happen outside of debugging and testing, but
        // make sure we catch it. Not using `assert()` to keep this enabled in
        // production code
        throw AssertionFailure("type-info has no to_string() callback");

    return _ti->_to_string(pointer());
}

namespace value {
/**
 * Retrieves the auxiliary type information for a value, casted it to the
 * expected class.
 *
 * @param  v value to retrieve information from
 * @return a reference to the auxiliary type information
 * @tparam Type the expected class for the auxiliary type information
 * @throws ``InvalidValue`` if the auxiliary type information does not have the expected type
 */
template<typename Type>
const Type* auxType(const type_info::Value& v) {
    const auto& type = v.type();

    if constexpr ( std::is_same_v<Type, type_info::Address> ) {
        assert(type.tag == TypeInfo::Address);
        return type.address;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Any> ) {
        assert(type.tag == TypeInfo::Any);
        return type.any;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Bitfield> ) {
        assert(type.tag == TypeInfo::Bitfield);
        return type.bitfield;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Bool> ) {
        assert(type.tag == TypeInfo::Bool);
        return type.bool_;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Bytes> ) {
        assert(type.tag == TypeInfo::Bytes);
        return type.bytes;
    }
    else if constexpr ( std::is_same_v<Type, type_info::BytesIterator> ) {
        assert(type.tag == TypeInfo::BytesIterator);
        return type.bytes_iterator;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Enum> ) {
        assert(type.tag == TypeInfo::Enum);
        return type.enum_;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Error> ) {
        assert(type.tag == TypeInfo::Error);
        return type.error;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Exception> ) {
        assert(type.tag == TypeInfo::Exception);
        return type.exception;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Function> ) {
        assert(type.tag == TypeInfo::Function);
        return type.function;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Interval> ) {
        assert(type.tag == TypeInfo::Interval);
        return type.interval;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Library> ) {
        assert(type.tag == TypeInfo::Library);
        return type.library;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Map> ) {
        assert(type.tag == TypeInfo::Map);
        return type.map;
    }
    else if constexpr ( std::is_same_v<Type, type_info::MapIterator> ) {
        assert(type.tag == TypeInfo::MapIterator);
        return type.map_iterator;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Network> ) {
        assert(type.tag == TypeInfo::Network);
        return type.network;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Null> ) {
        assert(type.tag == TypeInfo::Null);
        return type.null;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Optional> ) {
        assert(type.tag == TypeInfo::Optional);
        return type.optional;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Port> ) {
        assert(type.tag == TypeInfo::Port);
        return type.port;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Real> ) {
        assert(type.tag == TypeInfo::Real);
        return type.real;
    }
    else if constexpr ( std::is_same_v<Type, type_info::RegExp> ) {
        assert(type.tag == TypeInfo::RegExp);
        return type.regexp;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Result> ) {
        assert(type.tag == TypeInfo::Result);
        return type.result;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Set> ) {
        assert(type.tag == TypeInfo::Set);
        return type.set;
    }
    else if constexpr ( std::is_same_v<Type, type_info::SetIterator> ) {
        assert(type.tag == TypeInfo::SetIterator);
        return type.set_iterator;
    }
    else if constexpr ( std::is_same_v<Type, type_info::SignedInteger<int8_t>> ) {
        assert(type.tag == TypeInfo::SignedInteger_int8);
        return type.signed_integer_int8;
    }
    else if constexpr ( std::is_same_v<Type, type_info::SignedInteger<int16_t>> ) {
        assert(type.tag == TypeInfo::SignedInteger_int16);
        return type.signed_integer_int16;
    }
    else if constexpr ( std::is_same_v<Type, type_info::SignedInteger<int32_t>> ) {
        assert(type.tag == TypeInfo::SignedInteger_int32);
        return type.signed_integer_int32;
    }
    else if constexpr ( std::is_same_v<Type, type_info::SignedInteger<int64_t>> ) {
        assert(type.tag == TypeInfo::SignedInteger_int64);
        return type.signed_integer_int64;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Stream> ) {
        assert(type.tag == TypeInfo::Stream);
        return type.stream;
    }
    else if constexpr ( std::is_same_v<Type, type_info::StreamIterator> ) {
        assert(type.tag == TypeInfo::StreamIterator);
        return type.stream_iterator;
    }
    else if constexpr ( std::is_same_v<Type, type_info::StreamView> ) {
        assert(type.tag == TypeInfo::StreamView);
        return type.stream_view;
    }
    else if constexpr ( std::is_same_v<Type, type_info::String> ) {
        assert(type.tag == TypeInfo::String);
        return type.string;
    }
    else if constexpr ( std::is_same_v<Type, type_info::StrongReference> ) {
        assert(type.tag == TypeInfo::StrongReference);
        return type.strong_reference;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Struct> ) {
        assert(type.tag == TypeInfo::Struct);
        return type.struct_;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Time> ) {
        assert(type.tag == TypeInfo::Time);
        return type.time;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Tuple> ) {
        assert(type.tag == TypeInfo::Tuple);
        return type.tuple;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Union> ) {
        assert(type.tag == TypeInfo::Union);
        return type.union_;
    }
    else if constexpr ( std::is_same_v<Type, type_info::UnsignedInteger<uint8_t>> ) {
        assert(type.tag == TypeInfo::UnsignedInteger_uint8);
        return type.unsigned_integer_uint8;
    }
    else if constexpr ( std::is_same_v<Type, type_info::UnsignedInteger<uint16_t>> ) {
        assert(type.tag == TypeInfo::UnsignedInteger_uint16);
        return type.unsigned_integer_uint16;
    }
    else if constexpr ( std::is_same_v<Type, type_info::UnsignedInteger<uint32_t>> ) {
        assert(type.tag == TypeInfo::UnsignedInteger_uint32);
        return type.unsigned_integer_uint32;
    }
    else if constexpr ( std::is_same_v<Type, type_info::UnsignedInteger<uint64_t>> ) {
        assert(type.tag == TypeInfo::UnsignedInteger_uint64);
        return type.unsigned_integer_uint64;
    }
    else if constexpr ( std::is_same_v<Type, type_info::ValueReference> ) {
        assert(type.tag == TypeInfo::ValueReference);
        return type.value_reference;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Vector> ) {
        assert(type.tag == TypeInfo::Vector);
        return type.vector;
    }
    else if constexpr ( std::is_same_v<Type, type_info::VectorIterator> ) {
        assert(type.tag == TypeInfo::VectorIterator);
        return type.vector_iterator;
    }
    else if constexpr ( std::is_same_v<Type, type_info::Void> ) {
        assert(type.tag == TypeInfo::Void);
        return type.void_;
    }
    else if constexpr ( std::is_same_v<Type, type_info::WeakReference> ) {
        assert(type.tag == TypeInfo::WeakReference);
        return type.weak_reference;
    }
    else {
        throw RuntimeError("unhandled type");
    }
}
} // namespace value


// Forward declare static built-in type information objects.
extern const TypeInfo address;
extern const TypeInfo any;
extern const TypeInfo bool_;
extern const TypeInfo bytes_iterator;
extern const TypeInfo bytes;
extern const TypeInfo error;
extern const TypeInfo int16;
extern const TypeInfo int32;
extern const TypeInfo int64;
extern const TypeInfo int8;
extern const TypeInfo interval;
extern const TypeInfo library;
extern const TypeInfo network;
extern const TypeInfo null;
extern const TypeInfo port;
extern const TypeInfo real;
extern const TypeInfo regexp;
extern const TypeInfo stream_iterator;
extern const TypeInfo stream_view;
extern const TypeInfo stream;
extern const TypeInfo string;
extern const TypeInfo time;
extern const TypeInfo uint16;
extern const TypeInfo uint32;
extern const TypeInfo uint64;
extern const TypeInfo uint8;
extern const TypeInfo void_;

} // namespace type_info

} // namespace hilti::rt
