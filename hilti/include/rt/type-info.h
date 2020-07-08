// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <hilti/rt/exception.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/types/all.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

namespace hilti::rt {

struct TypeInfo;

namespace type_info {

/** Exception flagging incorrect use of type-info values. */
HILTI_EXCEPTION(InvalidValue, RuntimeError);

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
 * pointer refering the value's storage, and (2) type information describing
 * how to interpret the raw pointer. An instance may be in an invalid state
 * if there's no underlying value available (e.g., when dereferencing an
 * unset `optional`).
 *
 * Value instances are tied to a `Parent` instance. The value's data will
 * remain accessible only as long as the parent stays around. If that goes
 * away, deferencing will throw an error.
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
        : _ptr(ptr), _ti(ti), _parent_handle(parent.handle()) {
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

    /** Returns true if the instance is referring to a valid value. */
    operator bool() const { return _ptr != nullptr; }

private:
    // Throws if parent has expired.
    void check() const {
        if ( _parent_handle.expired() )
            throw InvalidValue("type info value expired");
    }

    const void* _ptr;
    const TypeInfo* _ti;
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
class DereferencableType {
public:
    /**
     * Type of a function that, given the outer value, returns a pointer to
     * the contained element.
     */
    using Accessor = std::function<const void*(const Value& v)>;

    /**
     * Constructor.
     *
     * @param vtype type of the contained elements
     * @param accessor function retrieving a pointer to the contained element
     */
    DereferencableType(const TypeInfo* vtype, Accessor accessor) : _vtype(vtype), _accessor(accessor) {}

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
    std::optional<std::any> _cur;
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
     * unset optional if the iterator is already refering to the final
     * location.
     *
     * 3. `deref`:: Given a previously created iterator of the internal type,
     * return a pointer to the storage of the element that the iterator
     * refers to.
     *
     */
    using Accessor = std::tuple<std::function<std::optional<std::any>(const Value&)>,    // begin()
                                std::function<std::optional<std::any>(const std::any&)>, // next()
                                std::function<const void*(const std::any&)>>;            // deref()

    /**
     * Constructor.
     *
     * @param etype type of the sequence's elements
     * @param accessor set of functions retrieving and manipulating an iterator to traverse the sequence of contained
     * elements
     */
    IterableType(const TypeInfo* etype, Accessor accessor) : _etype(etype), _accessor(std::move(accessor)) {}

    /** Returns a `Sequence` that can be iterated over to visit all the contained elements. */
    iterable_type::Sequence iterate(const Value& value) const {
        return iterable_type::Sequence(this, std::move(value));
    }

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

/** Type information for type ``bool`. */
class Bool : public detail::AtomicType<bool> {};

/** Type information for type ``bytes`. */
class Bytes : public detail::AtomicType<hilti::rt::Bytes> {};

/** Type information for type ``iterator<bytes>`. */
class BytesIterator : public detail::AtomicType<hilti::rt::bytes::Iterator> {};

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
class Library : public detail::ValueLessType {};

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
    std::optional<std::any> _cur;
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
    using Accessor = std::tuple<std::function<std::optional<std::any>(const Value&)>,                 // begin()
                                std::function<std::optional<std::any>(const std::any&)>,              // next()
                                std::function<std::pair<const void*, const void*>(const std::any&)>>; // deref()

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
    map::Sequence iterate(const Value& value) const { return map::Sequence(this, std::move(value)); }

    /**
     * Returns the type of the key of the elements, as passed into the
     * constructor.
     */
    const TypeInfo* keyType() const { return _ktype; }

    /**
     * Returns the type of the valye of the elements, as passed into the constructor.
     */
    const TypeInfo* valueType() const { return _vtype; }

    template<typename K, typename V>
    using iterator_pair =
        std::pair<typename hilti::rt::Map<K, V>::const_iterator, typename hilti::rt::Map<K, V>::const_iterator>;

    template<typename K, typename V>
    static Accessor accessor() {
        return std::make_tuple(
            [](const Value& v_) -> std::optional<std::any> { // begin()
                auto v = static_cast<const hilti::rt::Map<K, V>*>(v_.pointer());
                if ( v->cbegin() != v->cend() )
                    return std::make_pair(v->cbegin(), v->cend());
                else
                    return std::nullopt;
            },
            [](std::any i_) -> std::optional<std::any> { // next()
                auto i = std::any_cast<iterator_pair<K, V>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](std::any i_) -> std::pair<const void*, const void*> { // deref()
                auto i = std::any_cast<iterator_pair<K, V>>(i_);
                return std::make_pair(&(*i.first).first, &(*i.first).second);
            });
    }

private:
    friend class map::Iterator;

    const TypeInfo* _ktype;
    const TypeInfo* _vtype;
    const Accessor _accessor;
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
    using Accessor = std::function<std::pair<const void*, const void*>(const Value& v)>;

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
     * Returns the type of the valye of the elements, as passed into the constructor.
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

/** Auxiliary type information for type ``optional<T>`. */
class Optional : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

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
class Result : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

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
            [](const Value& v_) -> std::optional<std::any> {
                auto v = static_cast<const hilti::rt::Set<T>*>(v_.pointer());
                if ( v->begin() != v->end() )
                    return std::make_pair(v->begin(), v->end());
                else
                    return std::nullopt;
            },
            [](std::any i_) -> std::optional<std::any> {
                auto i = std::any_cast<iterator_pair<T>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](std::any i_) -> const void* {
                auto i = std::any_cast<iterator_pair<T>>(i_);
                return &*i.first;
            });
    }
};

/** Auxiliary type information for type ``iterator<set>`. */
class SetIterator : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

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
class StrongReference : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

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
    using Accessor = std::function<const void*(const Value& v)>;

    /**
     * Constructor.
     *
     * @param name ID of the field
     * @param type type of the field
     * @param offset offset of the field in number bytes inside the struct
     * @param accessor function returning a pointer to a fields value
     */
    Field(const char* name, const TypeInfo* type, std::ptrdiff_t offset, Accessor accessor = accessor_default)
        : name(name), type(type), offset(offset), accessor(std::move(accessor)) {}

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

    const std::string name; /**< ID of the field */
    const TypeInfo* type /**< type of the field */;

private:
    friend class type_info::Struct;

    // Internal wrapper around accessor that's used from ``Struct``.
    Value value(const Value& v) const { return Value(accessor(v), type, v); }

    const std::ptrdiff_t offset;
    const Accessor accessor;
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

    /** Returns the struct's field. */
    const auto& fields() const { return _fields; }

    /**
     * Returns a vector that can be iterated over to visit all the fields.
     *
     * @param v the value referring to the struct to iterate over
     *
     * @return a vector of pairs ``(field, value)`` where *field* is the
     * current ``struct_::Field` and *value* is the field's value.
     */
    auto iterate(const Value& v) const {
        std::vector<std::pair<const struct_::Field&, Value>> values;

        for ( const auto& f : _fields ) {
            auto x = Value(static_cast<const char*>(v.pointer()) + f.offset, f.type, v);
            values.emplace_back(f, f.value(x));
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

        for ( const auto& f : _elements )
            values.emplace_back(f, Value(static_cast<const char*>(v.pointer()) + f.offset, f.type, v));

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
    using Accessor = std::function<std::size_t(const Value& v)>;
    const size_t npos = std::variant_npos;

    /**
     * Constructor
     *
     * @param labels the union's fields
     * @param accessor accessor function returning the index of the currently set field
     */
    Union(std::vector<union_::Field> fields, Accessor accessor)
        : _fields(std::move(fields)), _accessor(std::move(accessor)) {}

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
class ValueReference : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

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
            [](const Value& v_) -> std::optional<std::any> { // begin()
                auto v = static_cast<const hilti::rt::Vector<T, Allocator>*>(v_.pointer());
                if ( v->begin() != v->end() )
                    return std::make_pair(v->begin(), v->end());
                else
                    return std::nullopt;
            },
            [](std::any i_) -> std::optional<std::any> { // next()
                auto i = std::any_cast<iterator_pair<T, Allocator>>(i_);
                auto n = std::make_pair(++i.first, i.second);
                if ( n.first != n.second )
                    return std::move(n);
                else
                    return std::nullopt;
            },
            [](std::any i_) -> const void* { // deref()
                auto i = std::any_cast<iterator_pair<T, Allocator>>(i_);
                return &*i.first;
            });
    }
};

/** Auxiliary type information for type ``iterator<vector>`. */
class VectorIterator : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

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
class WeakReference : public detail::DereferencableType {
public:
    using detail::DereferencableType::DereferencableType;

    template<typename T>
    static auto accessor() { // deref()
        return [](const Value& v) -> const void* {
            return static_cast<const hilti::rt::WeakReference<T>*>(v.pointer())->get();
        };
    }
};

} // namespace type_info

/**
 * Top-level type information structure describing one type. There's a
 * generic part applying to all types, plus a variant storing additional,
 * type-specific auxiliary information.
 */
struct TypeInfo {
    std::optional<const char*> id; /**< Spicy-side ID associated with the type, if any. */
    const char* display;           /**< String rendering of the type. */

    // clang-format off
    /**
     * Type-specific auxiliary information. This also acts as a tag defining
     * which kind of type is being described.
     */
    std::variant<
        type_info::Address,
        type_info::Any,
        type_info::Bool,
        type_info::Bytes,
        type_info::BytesIterator,
        type_info::Enum,
        type_info::Error,
        type_info::Exception,
        type_info::Function,
        type_info::Interval,
        type_info::Library,
        type_info::Map,
        type_info::MapIterator,
        type_info::Network,
        type_info::Optional,
        type_info::Port,
        type_info::Real,
        type_info::RegExp,
        type_info::Result,
        type_info::Set,
        type_info::SetIterator,
        type_info::SignedInteger<int8_t>,
        type_info::SignedInteger<int16_t>,
        type_info::SignedInteger<int32_t>,
        type_info::SignedInteger<int64_t>,
        type_info::Stream,
        type_info::StreamIterator,
        type_info::StreamView,
        type_info::String,
        type_info::StrongReference,
        type_info::Struct,
        type_info::Time,
        type_info::Tuple,
        type_info::Union,
        type_info::UnsignedInteger<uint8_t>,
        type_info::UnsignedInteger<uint16_t>,
        type_info::UnsignedInteger<uint32_t>,
        type_info::UnsignedInteger<uint64_t>,
        type_info::ValueReference,
        type_info::Vector,
        type_info::VectorIterator,
        type_info::Void,
        type_info::WeakReference
        > aux_type_info;
    // clang-format on
};

namespace type_info {

/**
 * Helper for variant dispatching, borrowed from
 * https://www.bfilipek.com/2019/02/2lines3featuresoverload.html.
 */
template<class... Ts>
struct overload : Ts... {
    using Ts::operator()...;
};

template<class... Ts>
overload(Ts...) -> overload<Ts...>;

namespace detail {

/**
 * Helper to returns the type of a variant's currently set item. From
 * https://stackoverflow.com/a/53697591.
 */
template<class V>
std::type_info const& var_type(V const& v) {
    return std::visit([](auto&& x) -> decltype(auto) { return typeid(x); }, v);
}
} // namespace detail

namespace value {

/**
 * Retrieves the auxiliary type information for a value, casted it to the
 * expected class.
 *
 * @param  v value to retrieve information from
 * @return a reference to the auxiliary type information
 * @tparam the expected class for the auxiliary type information
 * @throws ``InvalidValue`` if the auxiliary type information does not have the expected type
 */
template<typename T>
const T& auxType(const type_info::Value& v) {
    if ( auto x = std::get_if<T>(&v.type().aux_type_info) )
        return *x;
    else
        throw InvalidValue(fmt("unexpected variant state: have %s, but want %s\n",
                               type_info::detail::var_type(v.type().aux_type_info).name(), typeid(T).name()));
}
} // namespace value


// Forward declare static built-in type information objects.
extern TypeInfo address;
extern TypeInfo any;
extern TypeInfo bool_;
extern TypeInfo bytes_iterator;
extern TypeInfo bytes;
extern TypeInfo bytes;
extern TypeInfo error;
extern TypeInfo int16;
extern TypeInfo int32;
extern TypeInfo int64;
extern TypeInfo int8;
extern TypeInfo interval;
extern TypeInfo library;
extern TypeInfo network;
extern TypeInfo port;
extern TypeInfo real;
extern TypeInfo regexp;
extern TypeInfo stream_iterator;
extern TypeInfo stream_view;
extern TypeInfo stream;
extern TypeInfo string;
extern TypeInfo string;
extern TypeInfo time;
extern TypeInfo uint16;
extern TypeInfo uint32;
extern TypeInfo uint64;
extern TypeInfo uint8;
extern TypeInfo void_;

} // namespace type_info

} // namespace hilti::rt
