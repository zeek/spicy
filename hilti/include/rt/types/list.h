// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

/**
 * A list that for large part builds on std::list, but adds a couple of things:
 *
 *     - We add safe HILTIs-side iterators become detectably invalid when the main
 *       containers gets destroyed.
 */

#pragma once

#include <initializer_list>
#include <list>
#include <utility>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/types/list_fwd.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

template<typename T>
class List;

namespace list {

template<typename T>
class SafeIterator : public detail::iterator::SafeIterator<List<T>, typename List<T>::SafeIterator, SafeIterator<T>> {
public:
    using Base = detail::iterator::SafeIterator<List<T>, typename List<T>::SafeIterator, SafeIterator<T>>;
    using Base::Base;
};

template<typename T>
class SafeConstIterator
    : public detail::iterator::SafeIterator<const List<T>, typename List<T>::ConstIterator, SafeConstIterator<T>> {
public:
    using Base = detail::iterator::SafeIterator<const List<T>, typename List<T>::ConstIterator, SafeConstIterator<T>>;
    using Base::Base;
};

} // namespace list

/** HILTI's `List` is just strong typedef for `std::list`. */
template<typename T>
class List : protected std::list<T>, public detail::iterator::Controllee {
public:
    using L = std::list<T>;
    using C = detail::iterator::Controllee;

    using typename L::value_type;

    using ConstIterator = typename L::const_iterator;
    using SafeIterator = typename L::iterator;

    List() = default;
    List(std::initializer_list<T> xs) : L(std::move(xs)) {}
    List(const List&) = default;
    List(List&&) = default;

    List& operator=(const List&) = default;
    List& operator=(List&&) = default;

    // Methods of `std::list`.
    using L::begin;
    using L::emplace_back;
    using L::empty;
    using L::end;
    using L::push_back;

    friend bool operator==(const List& a, const List& b) {
        return static_cast<const L&>(a) == static_cast<const L&>(b);
    }

    friend bool operator!=(const List& a, const List& b) { return ! (a == b); }
};

namespace list {

// template<typename I, typename Function, typename O = typename std::result_of<Function>::type>
template<typename I, typename O, typename C>
hilti::rt::List<O> make(const C& input, std::function<O(I)> func) {
    hilti::rt::List<O> output;
    for ( auto&& i : input )
        output.emplace_back(func(i));

    return output;
}

template<typename I, typename O, typename C>
hilti::rt::List<O> make(const C& input, std::function<O(I)> func, std::function<bool(I)> pred) {
    hilti::rt::List<O> output;
    for ( auto&& i : input )
        if ( pred(i) )
            output.emplace_back(func(i));

    return output;
}

/** Place-holder type for an empty list that doesn't have a known element type. */
struct Empty {};

template<typename T>
inline bool operator==(const List<T>& v, const Empty& /*unused*/) {
    return v.empty();
}
template<typename T>
inline bool operator==(const Empty& /*unused*/, const List<T>& v) {
    return v.empty();
}
template<typename T>
inline bool operator!=(const List<T>& v, const Empty& /*unused*/) {
    return ! v.empty();
}
template<typename T>
inline bool operator!=(const Empty& /*unused*/, const List<T>& v) {
    return ! v.empty();
}

inline auto safe_begin(const Empty& x, detail::adl::tag /*unused*/) { return &x; }
inline auto safe_end(const Empty& x, detail::adl::tag /*unused*/) { return &x; }
} // namespace list

namespace detail::adl {
template<typename T>
inline std::string to_string(const List<T>& x, adl::tag /*unused*/) {
    return fmt("[%s]", rt::join(rt::transform(x, [](const T& y) { return rt::to_string(y); }), ", "));
}

inline std::string to_string(const list::Empty& x, adl::tag /*unused*/) { return "[]"; }

template<typename T>
inline std::string to_string(const list::SafeIterator<T>& /*unused*/, adl::tag /*unused*/) {
    return "<list iterator>";
}

template<typename T>
inline std::string to_string(const list::SafeConstIterator<T>& /*unused*/, adl::tag /*unused*/) {
    return "<const list iterator>";
}

template<typename T>
inline auto safe_begin(const List<T>& x, adl::tag /*unused*/) {
    return list::SafeConstIterator<T>(x, x.begin());
}

template<typename T>
inline auto safe_end(const List<T>& x, adl::tag /*unused*/) {
    return list::SafeConstIterator<T>(x, x.end());
}

template<typename T>
inline auto safe_begin(List<T>& x, adl::tag /*unused*/) {
    return list::SafeIterator<T>(x, x.begin());
}

template<typename T>
inline auto safe_end(List<T>& x, adl::tag /*unused*/) {
    return list::SafeIterator<T>(x, x.end());
}

} // namespace detail::adl

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const List<T>& x) {
    out << to_string(x);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const list::Empty& x) {
    out << to_string(x);
    return out;
}

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const list::SafeIterator<T>& x) {
    out << to_string(x);
    return out;
}

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const list::SafeConstIterator<T>& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
