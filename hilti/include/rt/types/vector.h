// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

/**
 * A vector that for large part built on std::vector, but adds a couple of things:
 *
 *     - We record if an element has been set at all.
 *     - We add safe HILTIs-side iterators become detectably invalid when the main
 *       containers gets destroyed.
 *     - We add auto-growth on assign.
 *     - We track which elements are set at all.
 */

#pragma once

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <ostream>
#include <type_traits>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

template<typename T, typename Allocator = std::allocator<T>>
class Vector;

namespace vector {

/**
 * Allocactor for `Vector` that initializes elements with a given default value.
 *
 * See https://howardhinnant.github.io/allocator_boilerplate.html and
 * https://stackoverflow.com/questions/48061522/create-the-simplest-allocator-with-two-template-arguments
 */
template<class T, T Default_>
class Allocator {
public:
    using value_type = T;

    value_type* allocate(std::size_t n) { return static_cast<value_type*>(::operator new(n * sizeof(value_type))); }

    void deallocate(value_type* p, std::size_t) noexcept { ::operator delete(p); }

    template<typename U>
    void construct(U* p) noexcept(std::is_nothrow_default_constructible<U>::value) {
        ::new (static_cast<void*>(p)) U(Default_);
    }

    template<typename U, typename... Args>
    void construct(U* p, Args&&... args) {
        ::new (p) U(std::forward<Args>(args)...);
    }

    template<class U>
    struct rebind {
        using other = Allocator<U, Default_>;
    };
};

template<class T, T D1, class U, U D2>
bool operator==(Allocator<T, D1> const&, Allocator<U, D2> const&) noexcept {
    return true;
}

template<class T, T D1, class U, U D2>
bool operator!=(Allocator<T, D1> const&, Allocator<U, D2> const&) noexcept {
    return false;
}

template<typename T, typename Allocator = std::allocator<T>>
class SafeIterator
    : public hilti::rt::detail::iterator::SafeIterator<
          Vector<T, Allocator>, typename Vector<T, Allocator>::SafeIterator, SafeIterator<T, Allocator>> {
public:
    using Base =
        hilti::rt::detail::iterator::SafeIterator<Vector<T, Allocator>, typename Vector<T, Allocator>::SafeIterator,
                                                  SafeIterator<T, Allocator>>;
    using Base::Base;
};

template<typename T, typename Allocator = std::allocator<T>>
class SafeConstIterator
    : public hilti::rt::detail::iterator::SafeIterator<
          const Vector<T, Allocator>, typename Vector<T, Allocator>::ConstIterator, SafeConstIterator<T, Allocator>> {
public:
    using Base = hilti::rt::detail::iterator::SafeIterator<
        const Vector<T, Allocator>, typename Vector<T, Allocator>::ConstIterator, SafeConstIterator<T, Allocator>>;
    using Base::Base;
};

} // namespace vector

// Proxy to faciliate safe assignment.

/** HILTI's `Vector` is just strong typedef for `std::vector`. */
template<typename T, typename Allocator>
class Vector : public std::vector<T, Allocator>, public hilti::rt::detail::iterator::Controllee {
public:
    using V = std::vector<T, Allocator>;
    using C = hilti::rt::detail::iterator::Controllee;

    using ConstIterator = typename V::const_iterator;
    using SafeIterator = typename V::iterator;

    Vector() = default;
    Vector(const Vector&) = default;
    Vector(Vector&&) noexcept = default;
    Vector(const std::list<T>& l) : std::vector<T>(l.begin(), l.end()) {}
    Vector(std::list<T>&& l) : std::vector<T>(std::move_iterator(l.begin()), std::move_iterator(l.end())) {}
    ~Vector() = default;

    /** Returns the first element of the vector. */
    const T& front() const {
        if ( V::empty() )
            throw IndexError("vector is empty");

        return V::front();
    }

    /** Returns the last element of the vector. */
    const T& back() const {
        if ( V::empty() )
            throw IndexError("vector is empty");

        return V::back();
    }

    Vector& operator=(const Vector&) = default;
    Vector& operator=(Vector&&) noexcept = default;

    const T& operator[](uint64_t i) const {
        if ( i >= V::size() )
            throw IndexError(fmt("vector index %" PRIu64 " out of range", i));

        return V::data()[i];
    }

    auto operator[](uint64_t i);

    Vector operator+(const Vector& other) const {
        Vector v(*this);
        v += other;
        return v;
    }

    Vector& operator+=(const Vector& other) {
        V::insert(V::end(), other.begin(), other.end());
        return *this;
    }
};

namespace vector::detail {

template<typename T, typename Allocator>
class AssignProxy {
public:
    using V = std::vector<T, Allocator>;

    AssignProxy(V* v, uint64_t i) : _v(v), _i(i) {}

    // TODO(robin): Not sure why we can't return by reference here, compiler says it
    // would be a temporary.
    T get() const {
        if ( _i >= _v->size() )
            throw IndexError(fmt("vector index %" PRIu64 " out of range", _i));

        return (*_v)[_i];
    }

    AssignProxy& operator=(T t) {
        _v->resize(std::max(static_cast<uint64_t>(_v->size()), _i + 1));
        (*_v)[_i] = std::move(t);
        return *this;
    }

    operator T() const { return get(); }

    bool operator==(const T& t) { return get() == t; }
    bool operator!=(const T& t) { return get() != t; }

private:
    V* _v;
    uint64_t _i;
};

} // namespace vector::detail

template<typename T, typename Allocator>
inline auto Vector<T, Allocator>::operator[](uint64_t i) {
    return hilti::rt::vector::detail::template AssignProxy<T, Allocator>(this, i);
}

template<typename T, typename Allocator>
inline std::ostream& operator<<(std::ostream& out, const hilti::rt::vector::detail::AssignProxy<T, Allocator>& x) {
    out << x.get();
    return out;
}

namespace vector {
/** Place-holder type for an empty vector that doesn't have a known element type. */
class Empty : public Vector<bool> {};

template<typename T, typename Allocator>
inline bool operator==(const Vector<T, Allocator>& v, const Empty& /*unused*/) {
    return v.empty();
}
template<typename T, typename Allocator>
inline bool operator==(const Empty& /*unused*/, const Vector<T, Allocator>& v) {
    return v.empty();
}
template<typename T, typename Allocator>
inline bool operator!=(const Vector<T, Allocator>& v, const Empty& /*unused*/) {
    return ! v.empty();
}
template<typename T, typename Allocator>
inline bool operator!=(const Empty& /*unused*/, const Vector<T, Allocator>& v) {
    return ! v.empty();
}
} // namespace vector

namespace detail::adl {
template<typename T, typename Allocator>
inline std::string to_string(const Vector<T, Allocator>& x, adl::tag /*unused*/) {
    using detail::adl::to_string;
    return fmt("[%s]",
               rt::join(rt::transform(x, [](const std::optional<T>& y) { return (y ? rt::to_string(*y) : "(unset)"); }),
                        ", "));
}

template<typename T, typename Allocator>
inline std::string to_string(const std::vector<T, Allocator>& x, adl::tag /*unused*/) {
    return to_string(static_cast<const Vector<T, Allocator>&>(x), adl::tag{});
}

template<typename T, typename Allocator>
inline std::string to_string(const vector::detail::AssignProxy<T, Allocator>& x, adl::tag /*unused*/) {
    return hilti::rt::to_string(x.get());
}

inline std::string to_string(const vector::Empty& /* x */, adl::tag /*unused*/) { return "[]"; }

template<typename T, typename Allocator>
inline std::string to_string(const vector::SafeIterator<T, Allocator>& /*unused*/, adl::tag /*unused*/) {
    return "<vector iterator>";
}

template<typename T, typename Allocator>
inline std::string to_string(const vector::SafeConstIterator<T, Allocator>& /*unused*/, adl::tag /*unused*/) {
    return "<const vector iterator>";
}

template<typename T, typename Allocator>
inline auto safe_begin(const Vector<T, Allocator>& x, adl::tag /*unused*/) {
    return vector::SafeConstIterator<T, Allocator>(x, x.begin());
}

template<typename T, typename Allocator>
inline auto safe_begin(Vector<T, Allocator>& x, adl::tag /*unused*/) {
    return vector::SafeIterator<T, Allocator>(x, x.begin());
}

template<typename T, typename Allocator>
inline auto safe_end(const Vector<T, Allocator>& x, adl::tag /*unused*/) {
    return vector::SafeConstIterator<T, Allocator>(x, x.end());
}

template<typename T, typename Allocator>
inline auto safe_end(Vector<T, Allocator>& x, adl::tag /*unused*/) {
    return vector::SafeIterator<T, Allocator>(x, x.end());
}

} // namespace detail::adl

template<typename T, typename Allocator>
inline std::ostream& operator<<(std::ostream& out, const Vector<T, Allocator>& x) {
    out << to_string(x);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const vector::Empty& x) {
    out << to_string(x);
    return out;
}

template<typename T, typename Allocator>
inline std::ostream& operator<<(std::ostream& out, const vector::SafeIterator<T, Allocator>& x) {
    out << to_string(x);
    return out;
}

template<typename T, typename Allocator>
inline std::ostream& operator<<(std::ostream& out, const vector::SafeConstIterator<T, Allocator>& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
