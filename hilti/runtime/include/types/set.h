// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

/**
 * A set that mostly builds on std::set, but adds a couple of things:
 *
 *     - We add safe HILTI-side iterators become detectably invalid when the main
 *       containers gets destroyed.
 *
 *     - [Future] Automatic element expiration.
 */

#pragma once

#include <algorithm>
#include <initializer_list>
#include <ranges>
#include <set>
#include <string>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/set_fwd.h>
#include <hilti/rt/types/vector_fwd.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace set {

template<typename T>
class Iterator {
    using S = Set<T>;

    using Control = typename S::Control::Ref;
    Control _control;
    typename S::S::iterator _iterator;

public:
    using iterator_category = typename S::S::iterator::iterator_category;
    using value_type = typename S::S::value_type;
    using difference_type = typename S::S::difference_type;
    using pointer = typename S::S::pointer;
    using reference = typename S::S::reference;

    Iterator() = default;

    typename S::reference operator*() const {
        // Iterators to `end` cannot be dereferenced.
        if ( _iterator == static_cast<const std::set<T>&>(_control.get()).end() )
            throw IndexError("iterator is invalid");

        return *_iterator;
    }

    Iterator& operator++() {
        if ( ! _control.isValid() )
            throw IndexError("iterator is invalid");

        ++_iterator;
        return *this;
    };

    Iterator operator++(int) {
        auto ret = *this;
        ++(*this); // Ensures the iterator is valid.
        return ret;
    }

    friend bool operator==(const Iterator& a, const Iterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot compare iterators into different sets");

        return a._iterator == b._iterator;
    }

    friend bool operator!=(const Iterator& a, const Iterator& b) { return ! (a == b); }

protected:
    friend class Set<T>;

    Iterator(typename S::S::iterator iterator, Control control)
        : _control(std::move(control)), _iterator(std::move(iterator)) {}
};

} // namespace set

/** HILTI's `Set` is a `std::set`-like type with additional safety guarantees.
 *
 * In particular it guarantees that iterators are either valid, or throw an
 * exception when accessed.
 *
 * If not otherwise specified, we follow the semantics on iterator invalidation
 * of `std::set` with the caveat that iterators which cannot be dereferenced
 * can become invalid through mutating `Set` operations. We still validate
 * invalid dereferencing of such iterators.
 *
 *     rt::Set<int> set;
 *     auto it = set.begin(); // Valid iterator which cannot be dereferenced.
 *
 *     // Mutating the set invalidates not dereferenceable iterators.
 *     set.insert(1);
 *
 *     *it; // Iterator now invalid, throws.
 *
 * If not otherwise specified, member functions have the semantics of
 * `std::set` member functions.
 * */
template<typename T>
class Set : protected std::set<T> {
public:
    using S = std::set<T>;

    using Control = control::Block<Set<T>, InvalidIterator>;
    Control _control{this};

    using reference = const T&;
    using const_reference = const T&;

    using iterator = typename set::Iterator<T>;
    using const_iterator = typename set::Iterator<T>;

    using key_type = T;
    using value_type = T;

    using size_type = integer::safe<uint64_t>;

    Set() = default;
    Set(const Set&) = default;
    Set(Set&&) noexcept = default;
    Set(const Vector<T>& l) : std::set<T>(l.begin(), l.end()) {}
    Set(std::initializer_list<T> l) : std::set<T>(std::move(l)) {}
    ~Set() = default;

    Set& operator=(const Set&) = default;
    Set& operator=(Set&&) noexcept = default;

    /** Checks whether an element is in the set.
     *
     * @param `t` the element to check for
     * @return `true` if the element is part of the set.
     */
    bool contains(const T& t) const { return this->count(t); }

    auto begin() const {
        return iterator(static_cast<const S&>(*this).begin(), empty() ? typename Control::Ref() : _control);
    }

    auto end() const {
        return iterator(static_cast<const S&>(*this).end(), empty() ? typename Control::Ref() : _control);
    }

    size_type size() const { return S::size(); }

    /** Removes an element from the set.
     *
     * This function invalidates all iterators into the set.
     *
     * @param key the element to remove
     * @return 1 if the element was in the set, 0 otherwise
     */
    size_type erase(const key_type& key) {
        // Update control block to invalidate all iterators previously created from it.
        _control.Reset();

        return static_cast<S&>(*this).erase(key);
    }

    /** Erases all elements from the set.
     *
     * This function invalidates all iterators into the set.
     */
    void clear() {
        // Update control block to invalidate all iterators previously created from it.
        _control.Reset();

        return static_cast<S&>(*this).clear();
    }

    /** Inserts value in the position as close as possible to hint.
     *
     * @param hint hint for the insertion position
     * @param value value to insert
     * @return iterator pointing to the inserted element
     * */
    iterator insert(iterator hint, const T& value) {
        auto it = S::insert(hint._iterator, value);
        return iterator(it, _control);
    }

    std::pair<iterator, bool> insert(const T& value) {
        auto [it, inserted] = S::insert(value);
        return {iterator(it, _control), inserted};
    }

    // Methods of `std::set`. These methods *must not* cause any iterator invalidation.
    using S::empty;

    friend bool operator==(const Set& a, const Set& b) { return static_cast<const S&>(a) == static_cast<const S&>(b); }
    friend bool operator!=(const Set& a, const Set& b) { return ! (a == b); }

    friend set::Iterator<T>;
};

namespace set {
/** Place-holder type for an empty set that doesn't have a known element type. */
class Empty : public Set<bool> {};

inline bool operator==(const Empty& /*unused*/, const Empty& /*unused*/) { return true; }

template<typename T>
inline bool operator==(const Set<T>& v, const Empty& /*unused*/) {
    return v.empty();
}

template<typename T>
inline bool operator==(const Empty& /*unused*/, const Set<T>& v) {
    return v.empty();
}

inline bool operator!=(const Empty& /*unused*/, const Empty& /*unused*/) { return false; }

template<typename T>
inline bool operator!=(const Set<T>& v, const Empty& /*unused*/) {
    return ! v.empty();
}

template<typename T>
inline bool operator!=(const Empty& /*unused*/, const Set<T>& v) {
    return ! v.empty();
}
} // namespace set

namespace detail::adl {
template<typename T>
inline std::string to_string(const Set<T>& x, adl::tag /*unused*/) {
    return fmt("{%s}", rt::join(std::ranges::transform_view(x, [](const T& y) { return rt::to_string(y); }), ", "));
}

inline std::string to_string(const set::Empty& x, adl::tag /*unused*/) { return "{}"; }

template<typename T>
inline std::string to_string(const set::Iterator<T>& /*unused*/, adl::tag /*unused*/) {
    return "<set iterator>";
}
} // namespace detail::adl

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const Set<T>& x) {
    out << to_string(x);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const set::Empty& x) {
    out << to_string(x);
    return out;
}

namespace set {
template<typename T>
inline std::ostream& operator<<(std::ostream& out, const Iterator<T>& x) {
    out << to_string(x);
    return out;
}
} // namespace set

} // namespace hilti::rt
