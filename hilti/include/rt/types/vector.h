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
#include <initializer_list>
#include <new>
#include <ostream>
#include <type_traits>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/types/vector_fwd.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

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
class Vector : protected std::vector<T, Allocator>, public hilti::rt::detail::iterator::Controllee {
public:
    using V = std::vector<T, Allocator>;
    using C = hilti::rt::detail::iterator::Controllee;

    using ConstIterator = typename V::const_iterator;
    using SafeIterator = typename V::iterator;

    Vector() = default;
    Vector(const Vector&) = default;
    Vector(Vector&&) noexcept = default;
    Vector(std::initializer_list<T> init, const Allocator& alloc = Allocator()) : V(std::move(init), alloc) {}
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

    const T& operator[](uint64_t i) const& {
        if ( i >= V::size() )
            throw IndexError(fmt("vector index %" PRIu64 " out of range", i));

        return V::data()[i];
    }

    T operator[](uint64_t i) && {
        if ( i >= V::size() )
            throw IndexError(fmt("vector index %" PRIu64 " out of range", i));

        return V::data()[i];
    }

    T& operator[](uint64_t i) & {
        if ( i >= V::size() )
            V::resize(i + 1);

        return V::data()[i];
    }

    Vector operator+(const Vector& other) const {
        Vector v(*this);
        v += other;
        return v;
    }

    Vector& operator+=(const Vector& other) {
        V::insert(V::end(), other.begin(), other.end());
        return *this;
    }

    // Methods of `std::vector`.
    using typename V::value_type;
    using V::at;
    using V::begin;
    using V::clear;
    using V::emplace_back;
    using V::empty;
    using V::end;
    using V::push_back;
    using V::reserve;
    using V::size;

    friend bool operator==(const Vector& a, const Vector& b) {
        return static_cast<const V&>(a) == static_cast<const V&>(b);
    }
};

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
    return fmt("[%s]", rt::join(rt::transform(x, [](const T& y) { return rt::to_string(y); }), ", "));
}

template<typename T, typename Allocator>
inline std::string to_string(const std::vector<T, Allocator>& x, adl::tag /*unused*/) {
    using detail::adl::to_string;
    return fmt("[%s]", rt::join(rt::transform(x, [](const T& y) { return rt::to_string(y); }), ", "));
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

template<typename T, typename Allocator>
bool operator!=(const Vector<T, Allocator>& a, const Vector<T, Allocator>& b) {
    return ! (a == b);
}

} // namespace hilti::rt
