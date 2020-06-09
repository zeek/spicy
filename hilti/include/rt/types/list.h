// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

/**
 * A list that for large part builds on std::list, but adds a couple of things:
 *
 *     - We add safe HILTIs-side iterators become detectably invalid when the main
 *       containers gets destroyed.
 */

#pragma once

#include <functional>
#include <initializer_list>
#include <iterator>
#include <list>
#include <memory>
#include <optional>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/types/list_fwd.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace list {

template<typename T>
class Iterator {
    using L = List<T>;

    std::weak_ptr<L*> _control;
    typename L::L::iterator _iterator;

public:
    using difference_type = typename L::L::iterator::difference_type;
    using value_type = typename L::L::iterator::value_type;
    using pointer = typename L::L::iterator::pointer;
    using reference = typename L::L::iterator::reference;
    using iterator_category = typename L::L::iterator::iterator_category;

    Iterator() = default;
    Iterator(typename L::L::iterator&& iterator, const typename L::C& control)
        : _control(control), _iterator(std::move(iterator)) {}

    reference operator*() const {
        if ( auto&& c = _container() ) {
            if ( _iterator == c->get().List<T>::L::end() )
                throw IndexError("iterator is invalid");

            return *_iterator;
        }

        throw InvalidIterator("bound object has expired");
    }

    Iterator& operator++() {
        if ( auto&& c = _container() ) {
            if ( _iterator == c->get().List<T>::L::end() )
                throw InvalidArgument("cannot advance iterator beyond the end of container");


            ++_iterator;
            return *this;
        }

        throw InvalidIterator("bound object has expired");
    }

    Iterator operator++(int) {
        auto ret = *this;
        ++(*this);
        return ret;
    }

    friend bool operator==(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different lists");
        return a._iterator == b._iterator;
    }

    friend bool operator!=(const Iterator& a, const Iterator& b) { return ! (a == b); }

private:
    std::optional<std::reference_wrapper<L>> _container() const {
        if ( auto l = _control.lock() ) {
            return {std::ref(**l)};
        }

        return std::nullopt;
    }
};

template<typename T>
class ConstIterator {
    using L = List<T>;

    std::weak_ptr<L*> _control;
    typename L::L::const_iterator _iterator;

public:
    using difference_type = typename L::L::const_iterator::difference_type;
    using value_type = typename L::L::const_iterator::value_type;
    using pointer = typename L::L::const_iterator::pointer;
    using reference = typename L::L::const_iterator::reference;
    using iterator_category = typename L::L::const_iterator::iterator_category;

    ConstIterator() = default;
    ConstIterator(typename L::L::const_iterator&& iterator, const typename L::C& control)
        : _control(control), _iterator(std::move(iterator)) {}

    reference operator*() const {
        if ( auto&& c = _container() ) {
            if ( _iterator == c->get().List<T>::L::cend() )
                throw IndexError("iterator is invalid");

            return *_iterator;
        }

        throw InvalidIterator("bound object has expired");
    }

    ConstIterator& operator++() {
        if ( auto&& c = _container() ) {
            if ( _iterator == c->get().List<T>::L::end() ) {
                throw InvalidArgument("cannot advance iterator beyond the end of container");
            }

            ++_iterator;
            return *this;
        }

        throw InvalidIterator("bound object has expired");
    }

    ConstIterator operator++(int) {
        auto ret = *this;
        ++(*this);
        return ret;
    }

    friend bool operator==(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different lists");
        return a._iterator == b._iterator;
    }

    friend bool operator!=(const ConstIterator& a, const ConstIterator& b) { return ! (a == b); }

private:
    std::optional<std::reference_wrapper<const L>> _container() const {
        if ( auto l = _control.lock() ) {
            return {std::cref(**l)};
        }

        return std::nullopt;
    }
};

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const list::Iterator<T>& x) {
    out << to_string(x);
    return out;
}

template<typename T>
inline std::ostream& operator<<(std::ostream& out, const list::ConstIterator<T>& x) {
    out << to_string(x);
    return out;
}

} // namespace list

/** HILTI's `List` is a `std::list`-like type with additional safety guarantees.
 *
 * In particular it guarantees that
 *
 * - iterators cannot go out of bounds
 * - iterators remain valid as long as the underlying data is around; unsafe
 *   access is caught at runtime
 *
 * If not otherwise specified, member functions have the semantics of
 * `sts::list` member functions.
 */
template<typename T>
class List : protected std::list<T> {
public:
    using L = std::list<T>;

    using typename L::const_reference;
    using typename L::reference;
    using typename L::size_type;
    using typename L::value_type;

    using C = std::shared_ptr<List*>;
    C _control = std::make_shared<List<T>*>(this);

    using const_iterator = list::ConstIterator<T>;
    using iterator = typename list::Iterator<T>;

    List() = default;
    List(std::initializer_list<T> xs) : L(std::move(xs)) {}
    List(const List&) = default;
    List(List&&) = default;

    List& operator=(const List&) = default;
    List& operator=(List&&) = default;

    auto begin() { return iterator(L::begin(), _control); }
    auto end() { return iterator(L::end(), _control); }

    auto cbegin() const { return const_iterator(L::begin(), _control); }
    auto cend() const { return const_iterator(L::end(), _control); }

    auto begin() const { return cbegin(); }
    auto end() const { return cend(); }

    // Methods of `std::list`.
    using L::emplace_back;
    using L::empty;
    using L::push_back;
    using L::size;

    friend bool operator==(const List& a, const List& b) {
        return static_cast<const L&>(a) == static_cast<const L&>(b);
    }

    friend bool operator!=(const List& a, const List& b) { return ! (a == b); }

    friend class list::ConstIterator<T>;
    friend class list::Iterator<T>;
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
struct Empty {
    auto begin() const& { return this; }
    auto end() const& { return this; }
};

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
inline std::string to_string(const list::Iterator<T>& /*unused*/, adl::tag /*unused*/) {
    return "<list iterator>";
}

template<typename T>
inline std::string to_string(const list::ConstIterator<T>& /*unused*/, adl::tag /*unused*/) {
    return "<const list iterator>";
}

template<typename T>
inline auto safe_begin(const List<T>& x, adl::tag /*unused*/) {
    return x.begin();
}

template<typename T>
inline auto safe_end(const List<T>& x, adl::tag /*unused*/) {
    return x.end();
}

template<typename T>
inline auto safe_begin(List<T>& x, adl::tag /*unused*/) {
    return x.begin();
}

template<typename T>
inline auto safe_end(List<T>& x, adl::tag /*unused*/) {
    return x.end();
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

} // namespace hilti::rt
