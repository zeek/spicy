// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/optional.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

template<typename K, typename V>
class Map;

namespace map {

template<typename K, typename V>
class Iterator {
    using M = Map<K, V>;

    using Control = typename M::Control::Ref;
    Control _control;
    typename M::M::iterator _iterator;

public:
    Iterator() = default;

    friend class Map<K, V>;

    friend bool operator==(const Iterator& a, const Iterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot compare iterators into different maps");

        return a._iterator == b._iterator;
    }

    friend bool operator!=(const Iterator& a, const Iterator& b) { return ! (a == b); }

    Iterator& operator++() {
        if ( ! _control.isValid() ) {
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
        // Iterators to `end` cannot be dereferenced.
        if ( _iterator == static_cast<const typename M::M&>(_control.get()).cend() )
            throw IndexError("iterator is invalid");

        return *_iterator;
    }

private:
    friend class Map<K, V>;

    Iterator(typename M::M::iterator iterator, Control control)
        : _control(std::move(control)), _iterator(std::move(iterator)) {}
};

template<typename K, typename V>
class ConstIterator {
    using M = Map<K, V>;

    using Control = typename M::Control::Ref;
    Control _control;
    typename M::M::const_iterator _iterator;

public:
    ConstIterator() = default;

    friend bool operator==(const ConstIterator& a, const ConstIterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot compare iterators into different sets");

        return a._iterator == b._iterator;
    }

    friend bool operator!=(const ConstIterator& a, const ConstIterator& b) { return ! (a == b); }

    ConstIterator& operator++() {
        if ( ! _control.isValid() )
            throw IndexError("iterator is invalid");

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
        auto&& data = _control.get();

        // Iterators to `end` cannot be dereferenced.
        if ( _iterator == static_cast<const typename M::M&>(data).cend() )
            throw IndexError("iterator is invalid");

        return *_iterator;
    }

private:
    friend class Map<K, V>;

    ConstIterator(typename M::M::const_iterator iterator, Control control)
        : _control(std::move(control)), _iterator(std::move(iterator)) {}
};

} // namespace map

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
 *     // Mutating the map invalidates not dereferenceable iterators.
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

    using Control = control::Block<Map<K, V>, InvalidIterator>;
    Control _control{this};

    using key_type = typename M::key_type;
    using value_type = typename M::value_type;
    using size_type = integer::safe<uint64_t>;

    using iterator = typename map::Iterator<K, V>;
    using const_iterator = typename map::ConstIterator<K, V>;

    Map() = default;
    Map(std::initializer_list<value_type> init) : M(std::move(init)) {}

    /** Checks whether a key is set in the map.
     *
     * @param `k` the key to check for
     * @return `true` if the key is set in the map
     */
    bool contains(const K& k) const { return this->find(k) != static_cast<const M&>(*this).end(); }

    /**
     * Attempts to get the value for a key.
     *
     * @param k key to retrieve
     * @return the value
     * @throw `IndexError` if `k` is not set in the map
     */
    const V& get(const K& k) const& {
        try {
            return this->at(k);
        } catch ( const std::out_of_range& ) {
            throw IndexError("key is unset");
        }
    }

    /**
     * Attempts to get the value for a key.
     *
     * @param k key to retrieve
     * @return the value
     * @throw `IndexError` if `k` is not set in the map
     */
    V& get(const K& k) & {
        try {
            return this->at(k);
        } catch ( const std::out_of_range& ) {
            throw IndexError("key is unset");
        }
    }

    /**
     * Attempts to get the value for a key.
     *
     * @param k key to retrieve
     * @return the value, or an unset optional if the key is not set in the map
     */
    hilti::rt::Optional<V> get_optional(const K& k) const& {
        if ( auto it = this->find(k); it != M::end() )
            return it->second;
        else
            return {};
    }

    /** Access an element by key
     *
     * @param k key of the element
     * @return a reference to the element
     * @throw `IndexError` if `k` is not set in the map
     */
    auto& operator[](const K& k) & { return this->get(k); }

    /** Access an element by key
     *
     * @param k key of the element
     * @return a reference to the element
     * @throw `IndexError` if `k` is not set in the map
     */
    const auto& operator[](const K& k) const& { return this->get(k); }

    /** Access an element by key
     *
     * This function invalidates all iterators into the map iff `k` was not present in the map.
     *
     * @param k key of the element
     * @return a reference to the element
     * @throw `IndexError` if `k` is not set in the map
     */
    auto operator[](const K& k) && { return this->get(k); }

    void index_assign(const K& key, V value) {
        if ( ! contains(key) )
            this->invalidateIterators();

        this->insert_or_assign(key, std::move(value));
    }

    auto begin() const { return this->cbegin(); }
    auto end() const { return this->cend(); }

    auto begin() { return iterator(static_cast<M&>(*this).begin(), _control); }
    auto end() { return iterator(static_cast<M&>(*this).end(), _control); }

    auto cbegin() const { return const_iterator(static_cast<const M&>(*this).begin(), _control); }
    auto cend() const { return const_iterator(static_cast<const M&>(*this).end(), _control); }

    size_type size() const { return M::size(); }

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

    friend bool operator==(const Map& a, const Map& b) { return static_cast<const M&>(a) == static_cast<const M&>(b); }
    friend bool operator!=(const Map& a, const Map& b) { return ! (a == b); }

private:
    friend map::Iterator<K, V>;
    friend map::ConstIterator<K, V>;

    void invalidateIterators() {
        // Update control block to invalidate all iterators previously created from it.
        _control.Reset();
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

template<typename K, typename V>
inline std::string to_string(const std::pair<const K, V>& x, adl::tag /*unused*/) {
    // Overloading for `Map::value_type` leads to ambiguities so we overload the desugared type `std::pair`.
    static_assert(std::is_same_v<typename Map<K, V>::value_type, std::pair<const K, V>>);
    return fmt("(%s, %s)", hilti::rt::to_string(x.first), hilti::rt::to_string(x.second));
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

} // namespace detail::adl

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const Map<K, V>& x) {
    return out << to_string(x);
}

template<typename K, typename V>
inline std::ostream& operator<<(std::ostream& out, const std::pair<K, V>& x) {
    // Overloading for `Map::value_type` leads to ambiguities so we overload the desugared type `std::pair`.
    static_assert(std::is_same_v<typename Map<K, V>::value_type, std::pair<const K, V>>);
    return out << to_string(x);
}

inline std::ostream& operator<<(std::ostream& out, const map::Empty& x) { return out << to_string(x); }

} // namespace hilti::rt
