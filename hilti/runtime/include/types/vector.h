// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

/**
 * A vector that for large part built on std::vector, but adds a couple of things:
 *
 *     - We record if an element has been set at all.
 *     - We add safe HILTI-side iterators become detectably invalid when the main
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
#include <iterator>
#include <memory>
#include <new>
#include <optional>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/vector_fwd.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace vector {

/**
 * Allocator for `Vector` that initializes elements with a given default value.
 *
 * See https://howardhinnant.github.io/allocator_boilerplate.html and
 * https://stackoverflow.com/questions/48061522/create-the-simplest-allocator-with-two-template-arguments
 *
 * We allow defaults with types differing from the allocated type (but
 * implicitly convertible to it) to support allocators over non-basic types,
 * see e.g.,
 * https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1907r1.html.
 */
template<class T, decltype(auto) Default_>
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

template<class T, decltype(auto) D1, class U, decltype(auto) D2>
bool operator==(Allocator<T, D1> const&, Allocator<U, D2> const&) noexcept {
    return true;
}

template<class T, decltype(auto) D1, class U, decltype(auto) D2>
bool operator!=(Allocator<T, D1> const&, Allocator<U, D2> const&) noexcept {
    return false;
}

template<typename T, typename Allocator>
class Iterator {
    using V = Vector<T, Allocator>;
    friend V;

    std::weak_ptr<V*> _control;
    typename V::size_type _index = 0;

public:
    using difference_type = typename V::V::iterator::difference_type;
    using value_type = typename V::V::iterator::value_type;
    using pointer = typename V::V::iterator::pointer;
    using reference = typename V::V::iterator::reference;
    using const_reference = typename V::V::const_reference;
    using iterator_category = typename V::V::iterator::iterator_category;

    Iterator() = default;
    Iterator(typename V::size_type&& index, const typename V::C& control)
        : _control(control), _index(std::move(index)) {}

    reference operator*();
    const_reference operator*() const;

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

    friend auto operator<(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index < b._index;
    }

    friend auto operator<=(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index <= b._index;
    }

    friend auto operator>(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index > b._index;
    }

    friend auto operator>=(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index >= b._index;
    }

    friend difference_type operator-(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot perform arithmetic with iterators into different vectors");
        return a._index - b._index;
    }

private:
    // NOTE: This function returns a mutable reference so calling functions need
    // to ensure to produce correct `const` semantics in the API exposed to users.
    std::optional<std::reference_wrapper<V>> _container() const;
};

template<typename T, typename Allocator>
class ConstIterator {
    using V = Vector<T, Allocator>;

    std::weak_ptr<Vector<T, Allocator>*> _control;
    typename V::size_type _index = 0;

public:
    using difference_type = typename V::V::const_iterator::difference_type;
    using value_type = typename V::V::const_iterator::value_type;
    using pointer = typename V::V::const_iterator::pointer;
    using reference = typename V::V::const_iterator::reference;
    using const_reference = typename V::V::iterator::reference;
    using iterator_category = typename V::V::const_iterator::iterator_category;

    ConstIterator() = default;
    ConstIterator(typename V::size_type&& index, const typename V::C& control)
        : _control(control), _index(std::move(index)) {}

    const_reference operator*() const;

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

    friend auto operator<(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index < b._index;
    }

    friend auto operator<=(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index <= b._index;
    }

    friend auto operator>(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index > b._index;
    }

    friend auto operator>=(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different vectors");
        return a._index >= b._index;
    }

    friend difference_type operator-(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot perform arithmetic with iterators into different vectors");
        return a._index - b._index;
    }

private:
    // NOTE: This function returns a mutable reference so calling functions need
    // to ensure to produce correct `const` semantics in the API exposed to users.
    std::optional<std::reference_wrapper<V>> _container() const;
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
    // We do not allow `Vector<bool>` since `std::vector::bool` is not a proper container but a proxy.
    static_assert(! std::is_same_v<T, bool>, "'Vector' cannot be used with naked booleans, use 'Bool'");

    using V = std::vector<T, Allocator>;

    using size_type = integer::safe<uint64_t>;
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

    /**
     * Removes the last element of the `vector`.
     *
     * @throw `IndexError` if the `Vector` is empty
     */
    void pop_back() {
        if ( V::empty() )
            throw IndexError("vector is empty");

        V::pop_back();
    }

    /**
     * Returns an iterator referring to a specific element.
     *
     * @param i index of element
     * @throw `IndexError` if the *i* is out of range.
     */
    const_iterator iteratorAt(uint64_t i) const {
        if ( i >= V::size() )
            throw IndexError(fmt("vector index %" PRIu64 " out of range", i));

        return const_iterator(static_cast<size_type>(i), _control);
    }

    /**
     * Extracts a subsequence from the vector.
     *
     * @param from start index
     * @param end end index (not including)
     * @returns new vector with a copy of the range's elements
     */
    Vector<T> sub(uint64_t start, uint64_t end) const {
        if ( end <= start || start >= V::size() )
            return {};

        if ( end >= V::size() )
            end = V::size();

        Vector<T> v;
        std::copy(V::begin() + start, V::begin() + end, std::back_inserter(v));
        return v;
    }

    /**
     * Extracts a subsequence from the vector.
     *
     * @param end end index (not including)
     * @returns new vector with a copy of the elements from the beginning to *end*
     */
    Vector<T> sub(uint64_t end) const {
        if ( end >= V::size() )
            end = V::size();

        Vector<T> v;
        std::copy(V::begin(), V::begin() + end, std::back_inserter(v));
        return v;
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
        if ( &other == this )
            return *this;

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
     * @param i position of the element to return
     * @return a reference to the element
     * @throw `IndexError` if the position is out of bounds.
     */
    T& operator[](uint64_t i) & {
        if ( i >= V::size() )
            throw IndexError(fmt("vector index %" PRIu64 " out of range", i));

        return V::data()[i];
    }

    /* Assigns a value to an element.
     *
     * If the element is not present in the vector, it is resized to contain
     * at i + 1 values. The other added values are default-initialized.
     *
     * @param i position of the element to assign
     * @param x value to assign
     */
    void assign(uint64_t i, T x) {
        if ( i >= V::size() )
            V::resize(i + 1);

        V::data()[i] = std::move(x);
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

    /** Inserts value before a given position.
     *
     * @param pos iterator to the position preceding the inserted value
     * @param value value to insert
     * @return iterator pointing to the inserted element
     * */
    iterator insert(iterator pos, const T& value) {
        const auto index = pos._index;
        if ( index > size() )
            throw InvalidIterator(fmt("index %s out of bounds", index));

        V::insert(V::begin() + index.Ref(), value);
        return pos;
    }

    auto begin() { return iterator(0U, _control); }
    auto end() { return iterator(size(), _control); }

    auto begin() const { return const_iterator(0U, _control); }
    auto end() const { return const_iterator(size(), _control); }

    auto cbegin() const { return const_iterator(0U, _control); }
    auto cend() const { return const_iterator(size(), _control); }

    size_type size() const { return V::size(); }

    // Methods of `std::vector`.
    using typename V::value_type;
    using V::at;
    using V::clear;
    using V::emplace_back;
    using V::empty;
    using V::pop_back;
    using V::push_back;
    using V::reserve;
    using V::resize;

    friend bool operator==(const Vector& a, const Vector& b) {
        return static_cast<const V&>(a) == static_cast<const V&>(b);
    }
};

namespace vector {
/** Place-holder type for an empty vector that doesn't have a known element type. */
struct Empty {
    auto begin() const& { return this; }
    auto end() const& { return this; }
    auto empty() const { return true; }
    auto size() const { return integer::safe<uint64_t>(0); }
};

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

template<typename Allocator, typename I, typename O, typename C>
Vector<O, Allocator> make(const C& input, std::function<O(I)> func) {
    Vector<O, Allocator> output;
    for ( auto&& i : input )
        output.emplace_back(func(i));

    return output;
}

template<typename Allocator, typename I, typename O, typename C>
Vector<O, Allocator> make(const C& input, std::function<O(I)> func, std::function<bool(I)> pred) {
    Vector<O, Allocator> output;
    for ( auto&& i : input )
        if ( pred(i) )
            output.emplace_back(func(i));

    return output;
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
typename vector::Iterator<T, Allocator>::reference vector::Iterator<T, Allocator>::operator*() {
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
typename vector::Iterator<T, Allocator>::const_reference vector::Iterator<T, Allocator>::operator*() const {
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
std::optional<std::reference_wrapper<Vector<T, Allocator>>> vector::Iterator<T, Allocator>::_container() const {
    if ( auto l = _control.lock() ) {
        return {std::ref(**l)};
    }

    return std::nullopt;
}

template<typename T, typename Allocator>
typename vector::ConstIterator<T, Allocator>::const_reference vector::ConstIterator<T, Allocator>::operator*() const {
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
std::optional<std::reference_wrapper<Vector<T, Allocator>>> vector::ConstIterator<T, Allocator>::_container() const {
    if ( auto l = _control.lock() ) {
        return {std::ref(**l)};
    }

    return std::nullopt;
}

} // namespace hilti::rt
