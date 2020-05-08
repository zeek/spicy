// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

/**
 * A map that mostly builds on std::map, but adds a couple of things:
 *
 *     - We add safe HILTI-side iterators become detectably invalid when the main
 *       containers gets destroyed.
 *
 *     - [Future] Automatic element expiration.
 */

#pragma once

#include <algorithm>
#include <initializer_list>
#include <map>
#include <memory>
#include <utility>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

template<typename K, typename V>
class Map;

namespace map {

template<typename K, typename V>
class SafeIterator : public hilti::rt::detail::iterator::SafeIterator<Map<K, V>, typename Map<K, V>::SafeIterator,
                                                                      SafeIterator<K, V>> {
public:
    using Base =
        hilti::rt::detail::iterator::SafeIterator<Map<K, V>, typename Map<K, V>::SafeIterator, SafeIterator<K, V>>;
    using Base::Base;
};

template<typename K, typename V>
class SafeConstIterator
    : public hilti::rt::detail::iterator::SafeIterator<const Map<K, V>, typename Map<K, V>::ConstIterator,
                                                       SafeConstIterator<K, V>> {
public:
    using Base = hilti::rt::detail::iterator::SafeIterator<const Map<K, V>, typename Map<K, V>::ConstIterator,
                                                           SafeConstIterator<K, V>>;
    using Base::Base;
};

} // namespace map

// Proxy to faciliate safe assignment.

/** HILTI's `Map` is an extended version `std::map`. */
template<typename K, typename V>
class Map : protected std::map<K, V>, public hilti::rt::detail::iterator::Controllee {
public:
    using M = std::map<K, V>;
    using C = hilti::rt::detail::iterator::Controllee;

    using value_type = typename M::value_type;

    using ConstIterator = typename M::const_iterator;
    using SafeIterator = typename M::iterator;

    Map() = default;
    Map(std::initializer_list<value_type> init) : M(std::move(init)) {}

    /** Returns true if a specific key is part of the set. */
    bool contains(const K& k) { return this->find(k) != this->end(); }

    /**
     * Returns the value for a given key, with an optional default if not foound.
     *
     * @param k key to retrieve
     * @param default_ if given, a defautl to return if *k* is not part of the map.
     *
     * @throws `IndexError` if `k` is not part of the map and no default has
     * been given.
     */
    const V& get(const K& k, std::optional<V> default_ = {}) const {
        if ( const auto& i = this->find(k); i != this->end() )
            return i->second;

        if ( default_ )
            return *default_;

        throw IndexError("key does not exist");
    }

    const V& operator[](const K& k) const { return get(k); }
    auto operator[](const K& k);

    // Methods of `std::map`.
    using M::begin;
    using M::clear;
    using M::end;
    using M::erase;
    using M::size;

    friend bool operator==(const Map& a, const Map& b) { return static_cast<const M&>(a) == static_cast<const M&>(b); }
    friend bool operator!=(const Map& a, const Map& b) { return ! (a == b); }
};

namespace map::detail {

template<typename K, typename V>
class AssignProxy {
public:
    using M = std::map<K, V>;

    AssignProxy(M* m, K k) : _m(m), _k(std::move(k)) {}

    const V& get() const {
        if ( _m->find(_k) != _m->end() )
            return (*_m)[_k];

        throw IndexError(fmt("map key does not exist"));
    }

    AssignProxy& operator=(V v) {
        (*_m)[_k] = std::move(v);
        return *this;
    }

    operator V() const { return get(); }

    bool operator==(const V& v) { return get() == v; }
    bool operator!=(const V& v) { return get() != v; }

private:
    M* _m;
    K _k;
};

} // namespace map::detail

template<typename K, typename V>
inline auto Map<K, V>::operator[](const K& k) {
    return hilti::rt::map::detail::template AssignProxy<K, V>(this, k);
}

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const hilti::rt::map::detail::AssignProxy<K, V>& x) {
    out << x.get();
    return out;
}

namespace map {
/** Place-holder type for an empty map that doesn't have a known element type. */
class Empty : public Map<bool, bool> {};

template<typename K, typename V>
inline bool operator==(const Map<K, V>& v, const Empty& /*unused*/) {
    return v.empty();
}
template<typename K, typename V>
inline bool operator==(const Empty& /*unused*/, const Map<K, V>& v) {
    return v.empty();
}
template<typename K, typename V>
inline bool operator!=(const Map<K, V>& v, const Empty& /*unused*/) {
    return ! v.empty();
}
template<typename K, typename V>
inline bool operator!=(const Empty& /*unused*/, const Map<K, V>& v) {
    return ! v.empty();
}
} // namespace map

namespace detail::adl {
template<typename K, typename V>
inline std::string to_string(const Map<K, V>& x, adl::tag /*unused*/) {
    std::vector<std::string> r;

    for ( const auto& i : x )
        r.push_back(fmt("%s: %s", i.first, i.second));

    return fmt("{%s}", rt::join(r, ", "));
}

template<typename K, typename V>
inline std::string to_string(const map::detail::AssignProxy<K, V>& x, adl::tag /*unused*/) {
    return hilti::rt::to_string(x.get());
}

inline std::string to_string(const map::Empty& x, adl::tag /*unused*/) { return "{}"; }

template<typename K, typename V>
inline std::string to_string(const map::SafeIterator<K, V>& /*unused*/, adl::tag /*unused*/) {
    return "<map iterator>";
}

template<typename K, typename V>
inline std::string to_string(const map::SafeConstIterator<K, V>& /*unused*/, adl::tag /*unused*/) {
    return "<const map iterator>";
}

template<typename K, typename V>
inline auto safe_begin(const Map<K, V>& x, adl::tag /*unused*/) {
    return map::SafeConstIterator<K, V>(x, x.begin());
}

template<typename K, typename V>
inline auto safe_begin(Map<K, V>& x, adl::tag /*unused*/) {
    return map::SafeIterator<K, V>(x, x.begin());
}

template<typename K, typename V>
inline auto safe_end(const Map<K, V>& x, adl::tag /*unused*/) {
    return map::SafeConstIterator<K, V>(x, x.end());
}

template<typename K, typename V>
inline auto safe_end(Map<K, V>& x, adl::tag /*unused*/) {
    return map::SafeIterator<K, V>(x, x.end());
}

} // namespace detail::adl

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const Map<K, V>& x) {
    out << to_string(x);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const map::Empty& x) {
    out << to_string(x);
    return out;
}

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const map::SafeIterator<K, V>& x) {
    out << to_string(x);
    return out;
}

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const map::SafeConstIterator<K, V>& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
