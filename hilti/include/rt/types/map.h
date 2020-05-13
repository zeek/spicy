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
#include <functional>
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
class Iterator {
    using M = Map<K, V>;

    std::weak_ptr<M*> _control;
    typename M::M::iterator _iterator;

public:
    Iterator() = default;

    friend class Map<K, V>;

    friend bool operator==(const Iterator& a, const Iterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different maps");

        return a._iterator == b._iterator;
    }

    friend bool operator!=(const Iterator& a, const Iterator& b) { return ! (a == b); }

    Iterator& operator++() {
        if ( ! _control.lock() ) {
            throw IndexError("iterator is invalid");
        }

        ++_iterator;
        return *this;
    }

    Iterator operator++(int) {
        auto ret = *this;
        ++(*this);
        return ret;
    }

    const typename M::M::value_type* operator->() const { return &operator*(); }

    typename M::M::const_reference operator*() const {
        if ( auto&& l = _control.lock() ) {
            // Iterators to `end` cannot be dereferenced.
            if ( _iterator == static_cast<const typename M::M&>(**l).cend() )
                throw IndexError("iterator is invalid");

            return *_iterator;
        }

        throw IndexError("iterator is invalid");
    }

private:
    friend class Map<K, V>;

    Iterator(typename M::M::iterator iterator, const typename M::C& control)
        : _control(control), _iterator(std::move(iterator)) {}
};

template<typename K, typename V>
class ConstIterator {
    using M = Map<K, V>;

    std::weak_ptr<M*> _control;
    typename M::M::const_iterator _iterator;

public:
    ConstIterator() = default;

    friend bool operator==(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control.lock() != b._control.lock() )
            throw InvalidArgument("cannot compare iterators into different sets");

        return a._iterator == b._iterator;
    }

    friend bool operator!=(const ConstIterator& a, const ConstIterator& b) { return ! (a == b); }

    ConstIterator& operator++() {
        if ( ! _control.lock() ) {
            throw IndexError("iterator is invalid");
        }

        ++_iterator;
        return *this;
    }

    ConstIterator operator++(int) {
        auto ret = *this;
        ++(*this);
        return ret;
    }

    const typename M::M::value_type* operator->() const { return &operator*(); }

    typename M::M::const_reference operator*() const {
        if ( auto&& l = _control.lock() ) {
            // Iterators to `end` cannot be dereferenced.
            if ( _iterator == static_cast<const typename M::M&>(**l).cend() )
                throw IndexError("iterator is invalid");

            return *_iterator;
        }

        throw IndexError("iterator is invalid");
    }

private:
    friend class Map<K, V>;

    ConstIterator(typename M::M::const_iterator iterator, const typename M::C& control)
        : _control(control), _iterator(std::move(iterator)) {}
};

namespace detail {

/** Proxy class for performing save assignments to `Map` entries.
 *
 * @note All methods accessing the underlying map are only defined for r-values
 * since this class only holds a reference to it. That makes it in general
 * unsafe to use these methods when the instance was bound to a later expired
 * `Map`. User should not need to `move` class instances to use them.
 */
template<typename K, typename V>
class AssignProxy {
    using M = Map<K, V>;

public:
    AssignProxy(K key, M& map) : _key(std::move(key)), _map(map) {}

    AssignProxy& operator=(V v) && {
        // If we insert a new element invalidate all iterators into the map.
        if ( ! _map.contains(_key) ) {
            _map.invalidateIterators();
        }

        auto& map = static_cast<typename M::M&>(_map);
        map[_key] = std::move(v);
        return *this;

        throw IndexError("cannot assign to expired key");
    }

    operator V() && { return _map.get(_key); }

    // We need to define an overload for const references for `hilti::to_string` to work.
    operator V() const& { return _map.get(_key); }

private:
    K _key;
    M& _map;
};

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const AssignProxy<K, V>& p) {
    return out << static_cast<V>(p);
}

} // namespace detail

} // namespace map

// Proxy to facilitate safe assignment.

/** HILTI's `Map` is a `std::map`-like type with additional safety guarantees.
 *
 * In particular it guarantees that iterators are either valid, or throw an
 * exception when accessed.
 *
 * If not otherwise specified, we follow the semantics on iterator invalidation
 * of `std::map` with the caveat that iterators which cannot be dereferenced
 * can become invalid through mutating `Map` operations. We still validate
 * invalid dereferencing of such iterators.
 *
 *     rt::Map<int, int> map;
 *     auto it = map.begin(); // Valid iterator which cannot be dereferenced.
 *
 *     // Mutating the map invalidates not dereferencable iterators.
 *     map.insert({1, 1});
 *
 *     *it; // Iterator now invalid, throws.
 *
 * If not otherwise specified, member functions have the semantics of
 * `std::map` member functions.
 * */
template<typename K, typename V>
class Map : protected std::map<K, V> {
public:
    using M = std::map<K, V>;
    using C = std::shared_ptr<Map<K, V>*>;

    C _control = std::make_shared<Map<K, V>*>(this);

    using key_type = typename M::key_type;
    using value_type = typename M::value_type;

    using iterator = typename map::Iterator<K, V>;
    using const_iterator = typename map::ConstIterator<K, V>;

    Map() = default;
    Map(std::initializer_list<value_type> init) : M(std::move(init)) {}

    /** Checks whether a key is set in the map.
     *
     * @param `k` the key to check for
     * @return `true` if the key is set in the map
     */
    bool contains(const K& k) { return this->find(k) != static_cast<const M&>(*this).end(); }

    /**
     * Attempts to get the value for a key.
     *
     * @param k key to retrieve
     * @return the value
     * @throw `IndexError` if `k` is not set in the map
     */
    const V& get(const K& k) const {
        try {
            return this->at(k);
        } catch ( const std::out_of_range& ) {
            throw IndexError("key is unset");
        }
    }

    /** Access an element by key
     *
     * This function invalidates all iterators into the map iff `k` was not present in the map.
     *
     * @param k key of the element
     * @return a reference to the element
     */
    auto operator[](const K& k) & { return map::detail::AssignProxy<K, V>(k, *this); }

    /** Access an element by key
     *
     * This function invalidates all iterators into the map iff `k` was not present in the map.
     *
     * @param k key of the element
     * @return a reference to the element
     * @throw `IndexError` if `k` is not set in the map
     */
    auto operator[](const K& k) const& { return this->get(k); }

    /** Access an element by key
     *
     * This function invalidates all iterators into the map iff `k` was not present in the map.
     *
     * @param k key of the element
     * @return a reference to the element
     * @throw `IndexError` if `k` is not set in the map
     */
    auto operator[](const K& k) && { return this->get(k); }

    auto begin() const { return this->cbegin(); }
    auto end() const { return this->cend(); }

    auto begin() { return iterator(static_cast<M&>(*this).begin(), _control); }

    auto end() { return iterator(static_cast<M&>(*this).end(), _control); }

    auto cbegin() const { return const_iterator(static_cast<const M&>(*this).begin(), _control); }

    auto cend() const { return const_iterator(static_cast<const M&>(*this).end(), _control); }


    /** Erases all elements from the map.
     *
     * This function invalidates all iterators into the map.
     */
    auto clear() {
        this->invalidateIterators();

        return static_cast<M&>(*this).clear();
    }

    /** Removes an element from the map.
     *
     * This function invalidates all iterators into the map iff an element was removed.
     *
     * @param key key of the element to remove
     * @return 1 if the element was in the set, 0 otherwise
     */
    auto erase(const key_type& key) {
        auto removed = static_cast<M&>(*this).erase(key);

        if ( removed ) {
            this->invalidateIterators();
        }

        return removed;
    }

    // Methods of `std::map`.
    using M::size;

    friend bool operator==(const Map& a, const Map& b) { return static_cast<const M&>(a) == static_cast<const M&>(b); }
    friend bool operator!=(const Map& a, const Map& b) { return ! (a == b); }

private:
    friend map::Iterator<K, V>;
    friend map::ConstIterator<K, V>;
    friend map::detail::AssignProxy<K, V>;

    void invalidateIterators() {
        // Update control block to invalidate all iterators previously created from it.
        _control = std::make_shared<Map<K, V>*>(this);
    }
}; // namespace hilti::rt

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

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const map::Iterator<K, V>& it) {
    return out << to_string(it);
}

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const map::ConstIterator<K, V>& it) {
    return out << to_string(it);
}
} // namespace map

namespace detail::adl {
template<typename K, typename V>
inline std::string to_string(const Map<K, V>& x, adl::tag /*unused*/) {
    std::vector<std::string> r;

    for ( const auto& i : x )
        r.push_back(fmt("%s: %s", hilti::rt::to_string(i.first), hilti::rt::to_string(i.second)));

    return fmt("{%s}", rt::join(r, ", "));
}

inline std::string to_string(const map::Empty& x, adl::tag /*unused*/) { return "{}"; }

template<typename K, typename V>
inline std::string to_string(const map::Iterator<K, V>& /*unused*/, adl::tag /*unused*/) {
    return "<map iterator>";
}

template<typename K, typename V>
inline std::string to_string(const map::ConstIterator<K, V>& /*unused*/, adl::tag /*unused*/) {
    return "<const map iterator>";
}

template<typename K, typename V>
inline std::string to_string(const map::detail::AssignProxy<K, V>& p, adl::tag /*unused*/) {
    return hilti::rt::to_string(V(p));
}

template<typename K, typename V>
inline auto safe_begin(const Map<K, V>& x, adl::tag /*unused*/) {
    return x.begin();
}

template<typename K, typename V>
inline auto safe_begin(Map<K, V>& x, adl::tag /*unused*/) {
    return x.begin();
}

template<typename K, typename V>
inline auto safe_end(const Map<K, V>& x, adl::tag /*unused*/) {
    return x.end();
}

template<typename K, typename V>
inline auto safe_end(Map<K, V>& x, adl::tag /*unused*/) {
    return x.end();
}

} // namespace detail::adl

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const Map<K, V>& x) {
    return out << to_string(x);
}

inline std::ostream& operator<<(std::ostream& out, const map::Empty& x) { return out << to_string(x); }

} // namespace hilti::rt
