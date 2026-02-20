// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cassert>
#include <memory>
#include <string>
#include <utility>
#include <variant>

#include <hilti/rt/any.h>
#include <hilti/rt/counted-ptr.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/types/struct.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace reference::detail {
void __attribute__((noreturn)) throw_null();
} // namespace reference::detail

/** Base for classes that `ValueReference::self` can receive.  */
template<typename T>
using Controllable = enable_counted_from_this<T>;

/**
 * Class representing HILTI's `value_ref<T>` type. This class stores an value
 * of type T on the heap and imposes value semantics on it. In particular,
 * copying a `ValueReference` will link the new instance to its own copy of
 * the managed value.
 *
 * Generally, a value reference will always have a value associated with it.
 * There are however ways to create it without one. Accesses that require a
 * value, are checked and will abort in that case.
 *
 * Other reference types (`StrongReference`, `WeakReference`) can bind to an
 * existing value reference, essentially creating handles to its value. They
 * then become joined managers of the value.
 *
 * @note It seems we could clean up this class and get rid of the internal
 * variant altogether. We need the variant only to potentially store a raw
 * pointer coming in through the corresponding constructor. However, we
 * require that pointer to point to a `Controllable` and hence could turn it
 * into a shared_ptr right there. On the downside, that would mean a
 * `shared_from_this()` call even if the resulting instance is never used --
 * which with the current code generator could happen frequently (at least
 * once we optimized to use `this` instead of the `self` wrapper when
 * possible). So leaving it alone for now.
 */
template<typename T>
class ValueReference {
public:
    /**
     * Instantiates a reference containing a new value of `T` initialized to
     * its default value.
     */
    ValueReference() : _ptr(make_counted<T>()) {}

    /**
     * Instantiates a reference containing a new value of `T` initialized to
     * a given value.
     *
     * @param t value to initialize new instance with
     */
    ValueReference(T t) : _ptr(make_counted<T>(std::move(t))) {}

    /**
     * Instantiates a new reference from an existing `std::shared_ptr` to a
     * value of type `T`. This does *not* copy the pointer's target value;
     * the new reference will keep a pointer to the same value.
     *
     * This constructor is mostly for internal purposes to create a new value
     * reference that's associated with an existing `StrongReference`.
     *
     * @param t shared pointer to link to
     */
    explicit ValueReference(counted_ptr<T> t) : _ptr(std::move(t)) {}

    /**
     * Copy constructor. The new instance will refer to a copy of the
     * source's value.
     */
    ValueReference(const ValueReference& other) {
        if ( auto ptr = other._get() )
            _ptr = make_counted<T>(*ptr);
        else
            _ptr = counted_ptr<T>();
    }

    /** Move constructor. */
    ValueReference(ValueReference&& other) noexcept = default;

    /** Destructor. */
    ~ValueReference() {}

    /**
     * Returns true if the reference does not contain a value. This will
     * rarely happen, except when explicitly constructed that way through an
     * existing pointer.
     */
    bool isNull() const {
        assert(_ptr.index() != std::variant_npos);
        return _get() == nullptr;
    }

    /**
     * Simply returns the value reference itself. This exists only is to make
     * the API compatible with other other reference types, which all offer the
     * same method.
     */
    const ValueReference<T>& derefAsValue() const { return *this; }

    /**
     * Simply returns the value reference itself. This exists only is to make
     * the API compatible with other other reference types, which all offer the
     * same method.
     */
    ValueReference<T>& derefAsValue() { return *this; }

    /**
     * Returns a pointer to the referred value. The result may be null if the
     * instance does not refer to a valid value.
     */
    const T* get() const { return _get(); }

    /**
     * Returns a shared pointer to the referred value. The result may be a
     * null pointer if the instance does not refer to a valid value.
     *
     * For this to work, the value reference must have either (1) create the
     * contained value itself through one of the standard constructor; or (2)
     * if created through an explicit pointer constructor, the instance must
     * be located on the heap and be the instance of a classed derived from
     * `Controllable<T>`.
     *
     * @throws IllegalReference if no shared pointer can be constructed for
     * the contained instance.
     */
    counted_ptr<T> asSharedPtr() const {
        assert(_ptr.index() != std::variant_npos);

        if ( auto x = std::get_if<counted_ptr<T>>(&_ptr) )
            return *x;

        try {
            if ( auto* ptr = std::get<T*>(_ptr) ) {
                if constexpr ( std::is_base_of_v<Controllable<T>, T> )
                    return ptr->shared_from_this();
                else
                    throw IllegalReference("cannot dynamically create reference for type");
            }
            else
                throw IllegalReference("unexpected state of value reference");
        } catch ( const std::bad_weak_ptr& ) {
            throw IllegalReference("reference to non-heap instance");
        }
    }

    /**
     * Resets the contained value to a fresh copy of a `T` value initialized
     * to its default.
     */
    void reset() { _ptr = counted_ptr<T>(); }

    /**
     * Returns a reference to the contained value.
     *
     * @throws NullReference if the instance does not refer to a valid value
     */
    const T& operator*() const { return *_safeGet(); }

    /**
     * Returns a reference to the contained value.
     *
     * @throws NullReference if the instance does not refer to a valid value
     */
    T& operator*() { return *_safeGet(); }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws NullReference if the instance does not refer to a valid value
     */
    const T* operator->() const { return _safeGet(); }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws NullReference if the instance does not refer to a valid value
     */
    T* operator->() { return _safeGet(); }

    /**
     * Implicitly converts to the contained type.
     *
     * @throws NullReference if the instance does not refer to a valid value
     */
    operator const T&() const { return *_safeGet(); }

    /**
     * Compares the values of two references.
     *
     * @throws NullReference if one of the instances does not refer to a
     * valid value
     */
    bool operator==(const ValueReference<T>& other) const { return *_safeGet() == *other._safeGet(); }

    /**
     * Compares the values of two references.
     *
     * @throws NullReference if one of the instances does not refer to a
     * valid value
     */
    bool operator==(const T& other) const { return *_safeGet() == other; }

    /**
     * Compares the values of two references.
     *
     * @throws NullReference if one of the instances does not refer to a
     * valid value
     */
    bool operator!=(const ValueReference<T>& other) const { return *_safeGet() != *other._safeGet(); }

    /**
     * Compares the values of two references.
     *
     * @throws NullReference if one of the instances does not refer to a
     * valid value
     */
    bool operator!=(const T& other) const { return *_safeGet() != other; }

    /**
     * Assigns to the contained value. Assigning does not invalidate other
     * references associated with the same value; they'll see the change.
     */
    ValueReference& operator=(T other) {
        if ( auto* ptr = _get() )
            *ptr = std::move(other);
        else
            _ptr = make_counted<T>(std::move(other));

        return *this;
    }

    /**
     * Assigns to the contained value. Assigning does not invalidate other
     * references associated with the same value; they'll see the change.
     */
    ValueReference& operator=(const ValueReference& other) noexcept {
        if ( &other == this )
            return *this;

        if ( ! other.get() ) {
            _ptr = nullptr;
            return *this;
        }

        // Not all types wrapped in a `ValueReference` might have a `noexcept`
        // assignment operator.
        try {
            if ( auto* ptr = _get() )
                *ptr = *other._get();
            else
                _ptr = make_counted<T>(*other._get());

            return *this;
        } catch ( ... ) {
            cannot_be_reached();
        }
    }

    /**
     * Assigns to the contained value. Assigning does not invalidate other
     * references associated with the same value; they'll see the change.
     */
    ValueReference& operator=(ValueReference&& other) noexcept {
        if ( &other == this )
            return *this;

        if ( ! other.get() ) {
            _ptr = nullptr;
            return *this;
        }

        // Not all types wrapped in a `ValueReference` might have a
        // `noexcept` (move) assignment operator.
        try {
            if ( auto* ptr = _get() ) {
                // We can't move the actual value as other references may be
                // referring to it.
                *ptr = *other._get();
                other._ptr = nullptr;
            }
            else
                _ptr = make_counted<T>(*other._get());

            return *this;
        } catch ( ... ) {
            cannot_be_reached();
        }
    }

    /**
     * Assigns from an existing `std::shared_ptr` to a value of type `T`. This
     * does *not* copy the pointer's target value; we will store a pointer to
     * the same value.
     */
    ValueReference& operator=(counted_ptr<T> other) noexcept {
        if ( _get() != other.get() )
            _ptr = std::move(other);

        return *this;
    }

    /**
     * Shortcut to create a new instance referring to an existing value of
     * type `T`. `T` must be derived from `Controllable<T>`.
     *
     * This is for internal use by the code generator to wrap `this` inside
     * methods into a value reference.
     */
    static ValueReference self(T* t) {
        static_assert(std::is_base_of_v<Controllable<T>, T>);
        assert(t);
        return ValueReference(t);
    }

private:
    /**
     * Instantiates a reference from an existing raw pointer to a value of
     * type 'T`, which must be derived from `Controllable<T>`.
     *
     * This does *not* copy the value being pointed to; the new
     * reference will keep a pointer to the same value. That also means it's
     * not safe to delete the pointed-to instance while the value reference
     * stays around.
     */
    explicit ValueReference(T* t) : _ptr(t) {
        static_assert(std::is_base_of_v<Controllable<T>, T>);
        assert(t);
    }

    const T* _get() const noexcept {
        if ( auto ptr = std::get_if<T*>(&_ptr) )
            return *ptr;

        assert(std::holds_alternative<counted_ptr<T>>(_ptr));
        return std::get_if<counted_ptr<T>>(&_ptr)->get();
    }

    T* _get() noexcept {
        if ( auto ptr = std::get_if<T*>(&_ptr) )
            return *ptr;

        assert(std::holds_alternative<counted_ptr<T>>(_ptr));
        return std::get_if<counted_ptr<T>>(&_ptr)->get();
    }

    const T* _safeGet() const {
        assert(_ptr.index() != std::variant_npos);

        if ( auto ptr = std::get_if<T*>(&_ptr); ptr && *ptr )
            return *ptr;

        if ( auto ptr = std::get_if<counted_ptr<T>>(&_ptr); ptr && *ptr )
            return ptr->get();

        reference::detail::throw_null();
    }

    T* _safeGet() {
        assert(_ptr.index() != std::variant_npos);

        if ( auto ptr = std::get_if<T*>(&_ptr); ptr && *ptr )
            return *ptr;

        if ( auto ptr = std::get_if<counted_ptr<T>>(&_ptr); ptr && *ptr )
            return ptr->get();

        reference::detail::throw_null();
    }

    // In `_safeGet` above we rely on the fact that a default-constructed
    // `ValueReference` always contains a `shared_ptr`, so it is listed as the
    // first variant.
    std::variant<counted_ptr<T>, T*> _ptr;
};

/**
 * A strong reference to a shared value. This is essentially a `shared_ptr`
 * that can bind to the values of `ValueReference` or `WeakReference.`
 *
 * Note that different from `ValueReference`, a strong reference can
 * explicitly be null.
 */
template<typename T>
class StrongReference : public counted_ptr<T> {
public:
    using Base = counted_ptr<T>;

    /** Default constructor creating a null reference. */
    StrongReference() : Base() {}

    /**
     * Instantiates a reference pointing to the value referred to be an
     * existing `ValueReference`. This does not copy the value, it will be
     * shared (and managed jointly) afterwards.
     */
    StrongReference(const ValueReference<T>& t) : Base(t.asSharedPtr()) {}

    /**
     * Instantiates a reference pointing to a newly allocated value.
     *
     * @param t initialization value
     */
    explicit StrongReference(T t) : Base(make_counted<T>(std::move(t))) {}

    /** Instantiate an unset reference. */
    explicit StrongReference(std::nullptr_t) {}

    /**
     * Copy constructor. This copies the reference, not the value, which will
     * be shared afterwards.
     */
    StrongReference(const StrongReference& other) : Base(other) {}

    /** Move constructor. */
    StrongReference(StrongReference&& other) noexcept : Base(std::move(other)) {}

    /**
     * Returns true if the reference does not refer any value.
     */
    bool isNull() const { return this->get() == nullptr; }

    /**
     * Returns a value reference that is linked to the referred value. If the
     * strong reference is null, the returned reference will be so, too.
     */
    ValueReference<T> derefAsValue() const { return ValueReference<T>(*this); }

    /**
     * Resets the reference to a null value, releasing any ownership it still
     * holds.
     */
    void reset() { Base::operator=(nullptr); }

    /**
     * Returns the contained value.
     *
     * @throws NullReference if the instance is null.
     */
    const T& operator*() const {
        _check();
        return *this->get(); // NOLINT
    }

    /**
     * Returns the contained value.
     *
     * @throws NullReference if the instance is null.
     */
    T& operator*() {
        _check();
        return *this->get(); // NOLINT
    }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws NullReference if the instance is null.
     */
    const T* operator->() const {
        _check();
        return this->get();
    }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws NullReference if the instance is null.
     */
    T* operator->() {
        _check();
        return this->get();
    }

    /** Returns true if the reference is not null. */
    explicit operator bool() const { return ! isNull(); }

    /**
     * Reinitializes the reference with a newly allocated value, releasing
     * any previous ownership still held.
     *
     * @param t value to allocate and then refer to
     */
    StrongReference& operator=(T other) {
        Base::operator=(make_counted<T>(std::move(other)));
        return *this;
    }

    /**
     * Reinitialized the reference to now point to to the value referred to
     * be an existing `ValueReference`. This does not copy that value, it
     * will be shared (and managed jointly) afterwards.
     */
    StrongReference& operator=(const ValueReference<T>& other) {
        Base::operator=(other.asSharedPtr());
        return *this;
    }

    /** Copy assignment. This will share ownership, not copy the value. */
    StrongReference& operator=(const StrongReference& other) {
        if ( &other == this )
            return *this;

        Base::operator=(other);
        return *this;
    }

    /** Move assignment. */
    StrongReference& operator=(StrongReference&& other) noexcept {
        Base::operator=(std::move(other));
        return *this;
    }

    /** Reset pointer. */
    StrongReference& operator=(std::nullptr_t) noexcept {
        Base::reset();
        return *this;
    }

private:
    void _check() const {
        if ( ! *this )
            reference::detail::throw_null();
    }
};

/**
 * A weak reference to a shared value. This is essentially a `weak_ptr` that
 * can bind to the values of `ValueReference` or `StrongReference.` The weak
 * reference will remain valid until all linked strong/value references have
 * ceased to exist.
 *
 * Note that different from `ValueReference`, a weak reference can explicitly
 * be null.
 */
template<typename T>
class WeakReference : public counted_weak_ptr<T> {
public:
    using Base = counted_weak_ptr<T>;

    /** Default constructor creating a null reference. */
    WeakReference() = default;

    /**
     * Instantiates a reference pointing to the value referred to be an
     * existing `ValueReference`. This does not copy the value, it will be
     * shared afterwards.
     */
    explicit WeakReference(const ValueReference<T>& t) : Base(t.asSharedPtr()) {}

    /**
     * Instantiates a reference pointing to the value referred to be an
     * existing `StrongReference`. This does not copy the value, it will be
     * shared afterwards.
     */
    explicit WeakReference(const StrongReference<T>& t) : Base(t) {}

    /** Instantiate an unset reference. */
    explicit WeakReference(std::nullptr_t) {}

    /**
     * Copy constructor. This copies the reference, not the value, which will
     * be shared afterwards.
     */
    WeakReference(const WeakReference& other) = default;

    /** Move constructor. */
    WeakReference(WeakReference&& other) noexcept = default;

    /** Destructor. */
    ~WeakReference() = default;

    /** Returns true if the reference is either null or expired. */
    bool isNull() const { return this->lock() == nullptr; }

    /**
     * Returns true if the reference was pointing to a non-null value that
     * has now expired.
     */
    bool isExpired() const {
        auto is_default = ! this->owner_before(Base{}) && ! Base{}.owner_before(*this);
        return this->expired() && ! is_default;
    }

    /**
     * Returns a pointer to the value being referred to. This will be null if
     * the weak point is null or expired.
     */
    const T* get() const { return this->lock().get(); }

    /**
     * Returns a value reference that is linked to the referred value. If the
     * weak reference is null or expired, the returned reference will be null.
     */
    ValueReference<T> derefAsValue() const { return ValueReference<T>(this->lock()); }

    /** Resets the reference to a null value. */
    void reset() { Base::reset(); }

    /**
     * Returns the contained value.
     *
     * @throws NullReference or ExpiredReference if the instance is null or
     * expired, respectively.
     */
    const T& operator*() const {
        _check();
        return *this->lock();
    }

    /**
     * Returns the contained value.
     *
     * @throws NullReference or ExpiredReference if the instance is null or
     * expired, respectively.
     */
    T& operator*() {
        _check();
        return *this->lock();
    }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws NullReference or ExpiredReference if the instance is null or
     * expired, respectively.
     */
    const T* operator->() const {
        _check();
        return this->lock().get();
    }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws NullReference or ExpiredReference if the instance is null or
     * expired, respectively.
     */
    T* operator->() {
        _check();
        return this->lock().get();
    }

    /** Returns true if the reference is not null or expired. */
    explicit operator bool() const { return ! isNull(); }

    /**
     * Reinitialize the reference to now point to to the value referred to
     * be an existing `ValueReference`. This does not copy that value, it
     * will be shared afterwards.
     */
    WeakReference& operator=(const ValueReference<T>& other) {
        Base::operator=(other.asSharedPtr());
        return *this;
    }

    /**
     * Reinitialize the reference to now point to to the value referred to
     * be an existing `StrongReference`. This does not copy that value, it
     * will be shared afterwards.
     */
    WeakReference& operator=(const StrongReference<T>& other) {
        Base::operator=(other);
        return *this;
    }

    /** Reset pointer. */
    WeakReference& operator=(std::nullptr_t) noexcept {
        Base::reset();
        return *this;
    }

    /** Copy assignment. This will share ownership, not copy the value. */
    WeakReference& operator=(const WeakReference& other) {
        if ( &other == this )
            return *this;

        Base::operator=(other);
        return *this;
    }

    /** Move assignment. */
    WeakReference& operator=(WeakReference&& other) noexcept {
        Base::operator=(std::move(other));
        return *this;
    }

private:
    void _check() const {
        if ( isExpired() )
            throw ExpiredReference("attempt to access expired reference");

        if ( isNull() )
            reference::detail::throw_null();
    }
};

/**
 * Type for a generic, non-templated strong reference binding to a StrongReference.
 * This generic version can keep a StrongReference alive, but provides
 * access to the instance itself only if the type is known.
 */
class StrongReferenceGeneric {
public:
    /** Leaves the reference unbound. */
    StrongReferenceGeneric() = default;

    /** Binds to the same instance as an existing strong reference.  */
    template<typename T>
    StrongReferenceGeneric(StrongReference<T> x) : _ptr(std::move(x)) {}

    /** Obtains a pointer to the stored value.
     * @returns a pointer to the bound instance, or null if unbound.
     * @throws IllegalReference if the target type does not match the stored reference type.
     * */
    template<typename T>
    T* as() const {
        if ( ! _ptr.has_value() )
            return nullptr;

        try {
            return hilti::rt::any_cast<StrongReference<T>>(_ptr).get();
        } catch ( const hilti::rt::bad_any_cast& ) {
            throw IllegalReference("invalid target type");
        }
    }

    /**
     * Returns a value reference that is linked to the referred value. If the
     * strong reference is null or expired, the returned reference will be
     * null.
     */
    template<typename T>
    ValueReference<T> derefAsValue() const {
        if ( ! _ptr.has_value() )
            return {};

        try {
            return hilti::rt::any_cast<StrongReference<T>>(_ptr).derefAsValue();
        } catch ( const hilti::rt::bad_any_cast& ) {
            throw IllegalReference("invalid target type");
        }
    }

    /** Releases the bound reference. */
    void reset() { _ptr.reset(); }

private:
    hilti::rt::any _ptr;
};

namespace reference {

/**
 * Helper to instantiate a strong reference pointing to a newly allocated,
 * preinitialized value.
 */
template<typename T, typename... Args>
StrongReference<T> make_strong(Args&&... args) {
    return StrongReference<T>(T(std::forward<Args>(args)...));
}

/**
 * Helper to instantiate a value reference pointing to a newly allocated,
 * preinitialized value.
 */
template<typename T, typename... Args>
ValueReference<T> make_value(Args&&... args) {
    return ValueReference<T>(T(std::forward<Args>(args)...));
}

} // namespace reference

namespace detail::adl {

template<typename T>
inline std::string to_string(const StrongReference<T>& x, adl::tag /*unused*/) {
    return x ? hilti::rt::to_string(*x) : "Null";
}

template<typename T>
inline std::string to_string(const WeakReference<T>& x, adl::tag /*unused*/) {
    if ( x.isExpired() )
        return "<expired ref>";

    if ( x.isNull() )
        return "Null";

    return hilti::rt::to_string(*x);
}

template<typename T>
inline std::string to_string(const ValueReference<T>& x, adl::tag /*unused*/) {
    return hilti::rt::to_string(*x);
}

} // namespace detail::adl

// String specialization

template<>
inline std::string detail::to_string_for_print<StrongReference<std::string>>(const StrongReference<std::string>& x) {
    return x ? hilti::rt::to_string_for_print(*x) : "Null";
}

template<>
inline std::string detail::to_string_for_print<WeakReference<std::string>>(const WeakReference<std::string>& x) {
    if ( x.isExpired() )
        return "<expired ref>";

    if ( x.isNull() )
        return "Null";

    return hilti::rt::to_string_for_print(*x);
}

template<>
inline std::string detail::to_string_for_print<ValueReference<std::string>>(const ValueReference<std::string>& x) {
    return hilti::rt::to_string_for_print(*x);
}

// Bytes specialization

template<>
inline std::string detail::to_string_for_print<StrongReference<Bytes>>(const StrongReference<Bytes>& x) {
    return x ? escapeBytes((*x).str()) : "Null";
}

template<>
inline std::string detail::to_string_for_print<WeakReference<Bytes>>(const WeakReference<Bytes>& x) {
    if ( x.isExpired() )
        return "<expired ref>";

    if ( x.isNull() )
        return "Null";

    return escapeBytes((*x).str());
}

template<>
inline std::string detail::to_string_for_print<ValueReference<Bytes>>(const ValueReference<Bytes>& x) {
    return escapeBytes((*x).str());
}

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const StrongReference<T>& x) {
    out << to_string(x);
    return out;
}

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const ValueReference<T>& x) {
    out << to_string(x);
    return out;
}

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const WeakReference<T>& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
