// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

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
#include <memory>
#include <set>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

template<typename T>
class Set;

namespace set {

template<typename T>
class SafeIterator
    : public hilti::rt::detail::iterator::SafeIterator<Set<T>, typename Set<T>::SafeIterator, SafeIterator<T>> {
public:
    using Base = hilti::rt::detail::iterator::SafeIterator<Set<T>, typename Set<T>::SafeIterator, SafeIterator<T>>;
    using Base::Base;
};

template<typename T>
class SafeConstIterator : public hilti::rt::detail::iterator::SafeIterator<const Set<T>, typename Set<T>::ConstIterator,
                                                                           SafeConstIterator<T>> {
public:
    using Base =
        hilti::rt::detail::iterator::SafeIterator<const Set<T>, typename Set<T>::ConstIterator, SafeConstIterator<T>>;
    using Base::Base;
};

} // namespace set

/** HILTI's `Set` is an extended version `std::set`. */
template<typename T>
class Set : public std::set<T>, public hilti::rt::detail::iterator::Controllee {
public:
    using V = std::set<T>;
    using C = hilti::rt::detail::iterator::Controllee;

    using ConstIterator = typename V::const_iterator;
    using SafeIterator = typename V::iterator;

    Set() = default;
    Set(const Set&) = default;
    Set(Set&&) noexcept = default;
    Set(const std::list<T>& l) : std::set<T>(l.begin(), l.end()) {}
    Set(std::list<T>&& l) : std::set<T>(std::move_iterator(l.begin()), std::move_iterator(l.end())) {}
    ~Set() = default;

    Set& operator=(const Set&) = default;
    Set& operator=(Set&&) noexcept = default;

    /** Returns true if a specific element is part of the set. */
    bool contains(const T& t) { return this->find(t) != this->end(); }
};

namespace set {
/** Place-holder type for an empty set that doesn't have a known element type. */
class Empty : public Set<bool> {};

template<typename T>
inline bool operator==(const Set<T>& v, const Empty& /*unused*/) {
    return v.empty();
}
template<typename T>
inline bool operator==(const Empty& /*unused*/, const Set<T>& v) {
    return v.empty();
}
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
    return fmt("{%s}", rt::join(rt::transform(x, [](const std::optional<T>& y) { return rt::to_string(y); }), ", "));
}

inline std::string to_string(const set::Empty& x, adl::tag /*unused*/) { return "{}"; }

template<typename T>
inline std::string to_string(const set::SafeIterator<T>& /*unused*/, adl::tag /*unused*/) {
    return "<set iterator>";
}

template<typename T>
inline std::string to_string(const set::SafeConstIterator<T>& /*unused*/, adl::tag /*unused*/) {
    return "<const set iterator>";
}

template<typename T>
inline auto safe_begin(const Set<T>& x, adl::tag /*unused*/) {
    return set::SafeConstIterator<T>(x, x.begin());
}

template<typename T>
inline auto safe_begin(Set<T>& x, adl::tag /*unused*/) {
    return set::SafeIterator<T>(x, x.begin());
}

template<typename T>
inline auto safe_end(const Set<T>& x, adl::tag /*unused*/) {
    return set::SafeConstIterator<T>(x, x.end());
}

template<typename T>
inline auto safe_end(Set<T>& x, adl::tag /*unused*/) {
    return set::SafeIterator<T>(x, x.end());
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

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const set::SafeIterator<T>& x) {
    out << to_string(x);
    return out;
}

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const set::SafeConstIterator<T>& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
