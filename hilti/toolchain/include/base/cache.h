// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>

namespace hilti::util {

/** Simple cache to remember a computed value for a given key. */
template<typename Key, typename Value>
class Cache {
public:
    using Callback1 = std::function<Value()>;
    using Callback2 = std::function<Value(Value& v)>;

    Cache() = default;

    /** Returns true if the cache has an entry for a given key. */
    bool has(const Key& key) const { return _cache.find(key) != _cache.end(); }

    /**
     * Returns the value for a given key, or optionally a default if not
     * found. Returning the default won't modify the cache.
     */
    std::optional<Value> get(const Key& key, std::optional<Value> default_ = {}) const {
        if ( auto i = _cache.find(key); i != _cache.end() )
            return i->second;

        return std::move(default_);
    }

    /**
     * Returns the value for a given key if it exists; or, if not, executes a
     * callback to compute a value. In the latter case the computed value
     * will be inserted into the cache before it's returned.
     */
    const Value& getOrCreate(const Key& key, const Callback1& cb) {
        if ( auto i = _cache.find(key); i != _cache.end() )
            return i->second;

        return put(key, cb());
    }

    /**
     * Returns the value for a given key if it exists; or, if not, executes a
     * a couple callbacks to compute a value. This splits the computation
     * into two parts to handle cases where it may recurse: the first
     * callback computes a prelimary value *v* that will be inserted into the
     * cache immediately. It will then be passed to the second callback to
     * compute the final value. If that second callback accesses the cache
     * with the same key during its operation, it will find *v*. The 2nd
     * callbacks result will update the cache on completion, although usually
     * it will probably just return *v* again to stay consistent.
     *
     */
    const Value& getOrCreate(const Key& key, const Callback1& cb1, const Callback2& cb2) {
        if ( auto i = _cache.find(key); i != _cache.end() )
            return i->second;

        _cache[key] = cb1();
        return _cache[key] = cb2(_cache[key]);
    }

    /** Stores a value for a key in the cache. */
    const Value& put(const Key& key, Value value) { return _cache[key] = std::move(value); }

    /** Removes an item from the cache. */
    void remove(const Key& key) { _cache.erase(key); }

private:
    std::map<Key, Value> _cache;
};

} // namespace hilti::util
