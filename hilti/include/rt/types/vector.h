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
#include <functional>
#include <initializer_list>
#include <memory>
#include <new>
#include <optional>
#include <ostream>
#include <type_traits>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/types/vector_fwd.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

/** Exception flagging invalid arguments passed to a function. */
HILTI_EXCEPTION(InvalidArgument, RuntimeError);

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

template<typename T, typename Allocator>
class Iterator {
    using V = Vector<T, Allocator>;

    std::weak_ptr<Vector<T, Allocator>*> _control;
    typename V::size_type _index = 0;

public:
    Iterator() = default;
    Iterator(typename V::size_type&& index, const typename V::C& control)
        : _control(control), _index(std::move(index)) {}

    typename V::reference operator*();

    Iterator& operator++() {
        ++_index;
        return *this;
    }

    Iterator operator++(int) {
        auto ret = *this;
        ++(*this);
        return ret;
    }

    friend bool operator==(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index == b._index;
    }

    friend bool operator!=(const Iterator& a, const Iterator& b) { return ! (a == b); }

private:
    std::optional<std::reference_wrapper<V>> _container();
};

template<typename T, typename Allocator>
class ConstIterator {
    using V = Vector<T, Allocator>;

    std::weak_ptr<Vector<T, Allocator>*> _control;
    typename V::size_type _index = 0;

public:
    ConstIterator() = default;
    ConstIterator(typename V::size_type&& index, const typename V::C& control)
        : _control(control), _index(std::move(index)) {}

    typename V::const_reference operator*();

    ConstIterator& operator++() {
        ++_index;
        return *this;
    }

    ConstIterator operator++(int) {
        auto ret = *this;
        ++(*this);
        return ret;
    }

    friend bool operator==(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index == b._index;
    }

    friend bool operator!=(const ConstIterator& a, const ConstIterator& b) { return ! (a == b); }

private:
    std::optional<std::reference_wrapper<V>> _container();
};

} // namespace vector

/** HILTI's `Vector` is a `std::vector`-like type with additional safety guarantees.
 *
 * In particular it guarantees that
 *
 * - bounds checking for subscript element access
 * - iterators remain valid when elements are added, removed, or the whole
 *   `Vector` is reassigned.
 *
 * If not otherwise specified, member functions have the semantics of
 * `std::vector` member functions.
 * */
template<typename T, typename Allocator>
class Vector : protected std::vector<T, Allocator> {
public:
    using V = std::vector<T, Allocator>;

    using size_type = typename V::size_type;
    using reference = T&;
    using const_reference = const T&;
    using iterator = vector::Iterator<T, Allocator>;
    using const_iterator = vector::ConstIterator<T, Allocator>;

    using C = std::shared_ptr<Vector*>;
    C _control = std::make_shared<Vector<T, Allocator>*>(this);

    Vector() = default;

    // Constructing from other `Vector` updates the data, but keeps the control block alive.
    Vector(const Vector& other) : V(other) {}
    Vector(Vector&& other) noexcept : V(std::move(other)) {}

    Vector(std::initializer_list<T> init, const Allocator& alloc = Allocator()) : V(std::move(init), alloc) {}

    Vector(const std::list<T>& l) : std::vector<T>(l.begin(), l.end()) {}
    Vector(std::list<T>&& l) : std::vector<T>(std::move_iterator(l.begin()), std::move_iterator(l.end())) {}
    ~Vector() = default;

    /** Returns the last element of the `vector`.
     *
     * @return a reference to the last element
     * @throw `IndexError` if the `Vector` is empty
     */
    const T& front() const {
        if ( V::empty() )
            throw IndexError("vector is empty");

        return V::front();
    }

    /** Returns the last element of the `vector`.
     *
     * @return a reference to the last element
     * @throw `IndexError` if the `Vector` is empty
     */
    const T& back() const {
        if ( V::empty() )
            throw IndexError("vector is empty");

        return V::back();
    }

    /** Replaces the contents of this `Vector` with another `Vector`.
     *
     * In contrast to assignments of `std::vector` iterators remain valid and
     * after assignment will point to positions in the assigned vector.
     *
     * @param other the `Vector` to assign
     * @return a reference to the changed `Vector`
     */
    Vector& operator=(const Vector& other) {
        static_cast<V&>(*this) = static_cast<const V&>(other);
        return *this;
    }

    /** Replaces the contents of this `Vector` with another `Vector`.
     *
     * In contrast to assignments of `std::vector` iterators remain valid and
     * after assignment will point to positions in the assigned vector.
     *
     * @param other the `Vector` to assign
     * @return a reference to the changed `Vector`
     */
    Vector& operator=(Vector&& other) noexcept {
        static_cast<V&>(*this) = static_cast<V&&>(std::move(other));
        return *this;
    }

    /** Accesses specified element.
     *
     * @param i position of the element to return
     * @return a reference to the element
     * @throw `IndexError` if the position is out of bounds.
     */
    const T& operator[](uint64_t i) const& {
        if ( i >= V::size() )
            throw IndexError(fmt("vector index %" PRIu64 " out of range", i));

        return V::data()[i];
    }

    /** Accesses specified element.
     *
     * @param i position of the element to return
     * @return the element
     * @throw `IndexError` if the position is out of bounds.
     */
    T operator[](uint64_t i) && {
        if ( i >= V::size() )
            throw IndexError(fmt("vector index %" PRIu64 " out of range", i));

        return V::data()[i];
    }

    /** Accesses specified element.
     *
     * This overload will attempt to resize the `Vector` so that a valid
     * element can be returned regardless of the current size of the `Vector`.
     *
     * @param i position of the element to return
     * @return a reference to the element
     */
    T& operator[](uint64_t i) & {
        if ( i >= V::size() )
            V::resize(i + 1);

        return V::data()[i];
    }

    /** Concatenates this `Vector` and another `Vector`.
     *
     * @param other the other `Vector` to append
     * @return the concatenation of this `Vector` and the other `Vector`
     */
    Vector operator+(const Vector& other) const {
        Vector v(*this);
        v += other;
        return v;
    }

    /** Appends a `Vector` in place.
     *
     * @param other the `Vector` to append
     * @return a reference to the modified `Vector`
     */
    Vector& operator+=(const Vector& other) {
        V::insert(V::end(), other.V::begin(), other.V::end());
        return *this;
    }

    auto begin() { return iterator(0u, _control); }
    auto end() { return iterator(size(), _control); }

    auto begin() const { return const_iterator(0u, _control); }
    auto end() const { return const_iterator(size(), _control); }

    auto cbegin() const { return const_iterator(0u, _control); }
    auto cend() const { return const_iterator(size(), _control); }

    // Methods of `std::vector`.
    using typename V::value_type;
    using V::at;
    using V::clear;
    using V::emplace_back;
    using V::empty;
    using V::pop_back;
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

inline std::string to_string(const vector::Empty& /* x */, adl::tag /*unused*/) { return "[]"; }

template<typename T, typename Allocator>
inline std::string to_string(const vector::Iterator<T, Allocator>& /*unused*/, adl::tag /*unused*/) {
    return "<vector iterator>";
}

template<typename T, typename Allocator>
inline std::string to_string(const vector::ConstIterator<T, Allocator>& /*unused*/, adl::tag /*unused*/) {
    return "<const vector iterator>";
}

template<typename T, typename Allocator>
inline auto safe_begin(const Vector<T, Allocator>& x, adl::tag /*unused*/) {
    return x.cbegin();
}

template<typename T, typename Allocator>
inline auto safe_begin(Vector<T, Allocator>& x, adl::tag /*unused*/) {
    return x.begin();
}

template<typename T, typename Allocator>
inline auto safe_end(const Vector<T, Allocator>& x, adl::tag /*unused*/) {
    return x.cend();
}

template<typename T, typename Allocator>
inline auto safe_end(Vector<T, Allocator>& x, adl::tag /*unused*/) {
    return x.end();
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
bool operator!=(const Vector<T, Allocator>& a, const Vector<T, Allocator>& b) {
    return ! (a == b);
}

template<typename T, typename Allocator>
typename Vector<T, Allocator>::reference vector::Iterator<T, Allocator>::operator*() {
    if ( auto&& c = _container() ) {
        auto&& data = c->get();

        if ( _index >= data.size() ) {
            throw InvalidIterator(fmt("index %s out of bounds", _index));
        }

        return data[_index];
    }

    throw InvalidIterator("bound object has expired");
}

namespace vector {

template<typename T, typename Allocator>
inline std::ostream& operator<<(std::ostream& out, const vector::Iterator<T, Allocator>& /*unused*/) {
    return out << "<vector iterator>";
}

template<typename T, typename Allocator>
inline std::ostream& operator<<(std::ostream& out, const vector::ConstIterator<T, Allocator>& /*unused*/) {
    return out << "<const vector iterator>";
}

} // namespace vector

template<typename T, typename Allocator>
std::optional<std::reference_wrapper<Vector<T, Allocator>>> vector::Iterator<T, Allocator>::_container() {
    if ( auto l = _control.lock() ) {
        return {std::ref(**l)};
    }

    return std::nullopt;
}

template<typename T, typename Allocator>
typename Vector<T, Allocator>::const_reference vector::ConstIterator<T, Allocator>::operator*() {
    if ( auto&& c = _container() ) {
        auto&& data = c->get();

        if ( _index >= data.size() ) {
            throw InvalidIterator(fmt("index %s out of bounds", _index));
        }

        return data[_index];
    }

    throw InvalidIterator("bound object has expired");
}

template<typename T, typename Allocator>
std::optional<std::reference_wrapper<Vector<T, Allocator>>> vector::ConstIterator<T, Allocator>::_container() {
    if ( auto l = _control.lock() ) {
        return {std::ref(**l)};
    }

    return std::nullopt;
}

} // namespace hilti::rt
