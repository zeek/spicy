// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <initializer_list>
#include <string>

#include <hilti/base/util.h>

namespace hilti::detail {

using normalizer_func = std::string (*)(std::string);
inline std::string identity_normalizer(std::string s) { return s; }

/**
 * Base class for representing scoped language IDs. It provides a number of
 * standard accesasorsd and manipulators to support operations on/with
 * namespaces. This class assumes that namespaces are seperated with `::`.
 *
 * @tparam Derived name of the class deriving from this one (CRTP).
 * @tparam N a function that may preprocess/normalize all ID components before storing them
 *
 */
template<class Derived, normalizer_func N = identity_normalizer>
class IDBase {
public:
    IDBase() = default;
    IDBase(const char* s) : _id(N(s)) {}
    explicit IDBase(std::string s) : _id(N(std::move(s))) {}

    /** Concatenates multiple strings into a single ID, separating them with `::`. */
    template<typename... T, typename enable = std::enable_if_t<(... && std::is_convertible_v<T, std::string>)>>
    explicit IDBase(const T&... s) : _id(N(util::join<std::string>({s...}, "::"))) {}

    /** Concatenates multiple strings into a single ID, separating them with `::`. */
    IDBase(const std::initializer_list<std::string>& x) : _id(util::join(x, "::")) {}

    /** Returns the ID's full name as a string. */
    auto str() const { return _id; }

    /** Returns the ID's namespace. That's everything except the local part. */
    Derived namespace_() const { return Derived(util::rsplit1(_id, "::").first); }

    /** Returns the ID local part. */
    Derived local() const { return Derived(util::rsplit1(_id, "::").second); }

    /** Returns true if the ID's value has length zero. */
    bool empty() const { return _id.empty(); }

    /**
     * Returns a new ID containing just single component of the path;s of the
     * ID. Indices are zero-based and, if negative, counted from the end
     * Python-style.
     *
     * @param i index of path component to return
     */
    Derived sub(int i) const {
        auto x = util::split(_id, "::");

        if ( i < 0 )
            i = x.size() + i;

        return Derived(i >= 0 && static_cast<size_t>(i) < x.size() ? x[i] : "");
    }

    /**
     * Returns a new ID containing a subpath of the ID. Indices are
     * zero-based and, if negative, counted from the end Python-style.
     *
     * @param from 1st index to include
     * @param to one beyond last index to include
     */
    Derived sub(int from, int to) const {
        return Derived(util::join(util::slice(util::split(_id, "::"), from, to), "::"));
    }

    /**
     * Returns a new ID containing the a subpath of the ID, starting at the
     * beginning.
     *
     * @param n number of path components to include
     */
    Derived firstN(int n) const { return Derived(sub(0, -1 - n)); }

    /**
     * Returns a new ID containing the a subpath of the ID, starting at the
     * end.
     *
     * @param n number of path components to include
     */
    Derived lastN(int n) const { return Derived(sub(-1 - n, -1)); }

    /**
     * "Rebases" the ID relative to another one.
     *
     * If the ID already starts with `root`, the remaining part is returned.
     * If not, the returned value is `root` plus the ID.
     */
    Derived relativeTo(const IDBase& root) const {
        if ( _id == root._id )
            return Derived();

        if ( ! util::startsWith(_id, root._id + "::") )
            return Derived(root, _id);

        return Derived(_id.substr(root._id.size() + 2));
    }

    /** Concantenates two IDs, separating them wiht `::`. */
    Derived operator+(const std::string& other) const {
        Derived n(_id);
        n += N(other);
        return n;
    }

    /** Concantenates two IDs, separating them wiht `::`. */
    Derived operator+(const IDBase& other) const {
        Derived n(_id);
        n += other;
        return n;
    }

    /** Appends an ID, separating it with `::`. */
    Derived& operator+=(std::string other) {
        if ( ! other.empty() ) {
            if ( _id.empty() )
                _id = N(std::move(other));
            else
                _id += "::" + N(std::move(other));
        }

        return static_cast<Derived&>(*this);
    }

    /** Appends an ID, separating it with `::`. */
    Derived& operator+=(const IDBase& other) {
        if ( ! other._id.empty() ) {
            if ( other._id.empty() )
                _id = other._id;
            else
                _id += "::" + other._id;
        }

        return static_cast<Derived&>(*this);
    }

    bool operator==(const IDBase& other) const { return _id == other._id; };
    bool operator!=(const IDBase& other) const { return _id != other._id; };
    bool operator==(const std::string& other) const { return _id == N(other); }
    bool operator!=(const std::string& other) const { return _id != N(other); }
    bool operator<(const IDBase& other) const { return _id < other._id; };

    explicit operator bool() const { return ! empty(); }
    operator std::string() const { return _id; }

protected:
    struct AlreadyNormalized {};

    /** no normalization */
    IDBase(std::string id, AlreadyNormalized /*unused*/) : _id(std::move(id)) {}

private:
    std::string _id;
};

} // namespace hilti::detail
