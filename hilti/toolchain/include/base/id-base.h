// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/base/util.h>

namespace hilti::detail {

using normalizer_func = std::optional<std::string> (*)(std::string_view);
inline std::optional<std::string> identityNormalizer(std::string_view s) { return std::nullopt; }

/**
 * Base class for representing scoped language IDs. It provides a number of
 * standard accessors and manipulators to support operations on/with
 * namespaces. This class assumes that namespaces are separated with `::`.
 *
 * @tparam Derived name of the class deriving from this one (CRTP).
 * @tparam N a function that may preprocess/normalize all ID components before storing them
 *
 */
template<class Derived, normalizer_func N = identityNormalizer>
class IDBase {
public:
    /** Tag for creating IDs from an already normalized string. */
    struct AlreadyNormalized {};

    ~IDBase() = default;

    IDBase& operator=(const IDBase& other) {
        if ( &other == this )
            return *this;

        _id = other._id;
        _views.reset();
        return *this;
    }

    IDBase& operator=(IDBase&& other) noexcept {
        if ( &other == this )
            return *this;

        _id = std::move(other._id);
        _views.reset();
        return *this;
    }

    /** Returns the ID's full name as a string. */
    const std::string& str() const { return _id; }

    /** Returns the ID local part, which is the most-rhs element of the ID path. */
    Derived local() const { return Derived(_cachedViews()->local, AlreadyNormalized()); }

    /** Returns the ID's namespace. That's everything except the local part. */
    Derived namespace_() const { return Derived(_cachedViews()->namespace_, AlreadyNormalized()); }

    /** Returns true if the ID's value has length zero. */
    bool empty() const { return _id.empty(); }

    /** Returns the number of namespace components. */
    size_t length() const { return _cachedViews()->path.size(); }

    /**  Returns true if the ID is absolute, i.e., starts with `::`. */
    bool isAbsolute() const { return ! _id.empty() && _id[0] == ':'; }

    /**
     * Returns a new ID containing just single component of the path's of the
     * ID. Indices are zero-based and, if negative, counted from the end
     * Python-style.
     *
     * @param i index of path component to return
     */
    Derived sub(int i) const {
        const auto& path = _cachedViews()->path;

        if ( i < 0 )
            i = static_cast<int>(path.size()) + i;

        if ( i >= 0 && static_cast<size_t>(i) < path.size() )
            return Derived(path[i], AlreadyNormalized());
        else
            return Derived();
    }

    /**
     * Returns a new ID containing a subpath of the ID. Indices are
     * zero-based and, if negative, counted from the end Python-style.
     *
     * @param from 1st index to include
     * @param to one beyond last index to include
     */
    Derived sub(int from, int to) const {
        return Derived(util::join(util::slice(_cachedViews()->path, from, to), "::"), AlreadyNormalized());
    }

    /**
     * "Rebases" the ID relative to another one.
     *
     * If the ID already starts with `root`, the remaining part is returned.
     * If not, the returned value is `root` plus the ID.
     */
    Derived relativeTo(const Derived& root) const {
        if ( _id == root._id )
            return Derived();

        if ( ! util::startsWith(_id, root._id + "::") )
            return Derived(root + _id, AlreadyNormalized());

        return Derived(_id.substr(root._id.size() + 2), AlreadyNormalized());
    }

    /**
     * Turns the ID into absolute one, i.e., prepends `::` if not already
     * present. Aftwerwards, `isAbsolute()` will return true.
     */
    Derived makeAbsolute() const {
        if ( isAbsolute() )
            return Derived(*this);

        return Derived("::" + _id, AlreadyNormalized());
    }

    /** Appends an ID, separating it with `::`. */
    Derived& operator+=(const Derived& other) {
        if ( ! other.empty() ) {
            if ( empty() )
                *this = other;
            else
                *this = Derived(_id + "::" + other._id, AlreadyNormalized());
        }

        return static_cast<Derived&>(*this);
    }

    /** Appends an ID, separating it with `::`. */
    Derived& operator+=(std::string_view other) {
        auto other_ = Derived(other);
        return *this += other_;
    }

    /** Concatenates two IDs, separating them with `::`. */
    Derived operator+(std::string_view other) const {
        Derived n = Derived(*this);
        n += other;
        return n;
    }

    /** Concatenates two IDs, separating them with `::`. */
    Derived operator+(const Derived& other) const {
        Derived n = Derived(*this);
        n += other;
        return n;
    }

    bool operator==(const Derived& other) const { return _id == other._id; };
    bool operator!=(const Derived& other) const { return ! (*this == other); }
    bool operator<(const Derived& other) const { return _id < other._id; };

    /** Returns true if the ID is not empty. */
    explicit operator bool() const { return ! empty(); }

    /** Returns the ID as a string, with all components normalized. */
    operator std::string() const { return _id; }

    /** Returns the ID as a string, with all components normalized. */
    operator std::string_view() const { return _id; }

private:
    friend Derived;

    /** Creates an empty ID. */
    IDBase() { _init("", false); }

    /** Creates an ID from an (not normalized) string. */
    IDBase(const char* s) { _init(s, false); }
    explicit IDBase(std::string_view s) { _init(s, false); }

    /**
     * Creates an ID from a string that's already normalized. The assumption is
     * that the input string is the output of a prior `str()` call on an
     * existing ID object.
     */
    IDBase(std::string_view s, AlreadyNormalized) { _init(s, true); }

    /** Concatenates multiple strings into a single ID, separating them with `::`. */
    template<typename... T, typename enable = std::enable_if_t<(... && std::is_convertible_v<T, std::string_view>)>>
    explicit IDBase(const T&... s) {
        _init((util::join(std::initializer_list<std::string_view>{s...}, "::")), false);
    }

    /** Concatenates multiple strings into a single ID, separating them with `::`. */
    IDBase(std::initializer_list<std::string_view> x) { _init(util::join(x, "::"), false); }

    IDBase(const IDBase& other) : _id(other._id) {}

    IDBase(IDBase&& other) noexcept : _id(std::move(other._id)) {}

    // Caches views into the ID string.
    struct Views {
        std::vector<std::string_view> path; // views into _id; empty for empty ID
        std::string_view local;             // view into _id
        std::string_view namespace_;        // view into _id
    };

    void _init(std::string_view s, bool already_normalized) {
        if ( s.empty() )
            return;

        if ( already_normalized )
            _id = s;

        else {
            _id.reserve(s.size()); // we'll need at least this much
            for ( size_t i = 0; i < s.size(); /* empty */ ) {
                if ( auto p = s.find("::", i); p != std::string::npos ) {
                    _normalizeAndAdd(s.substr(i, p - i));
                    _id += "::";
                    i = p + 2;
                }
                else {
                    _normalizeAndAdd(s.substr(i));
                    break;
                }
            }
        }
    }

    void _normalizeAndAdd(std::string_view x) {
        assert(x.find("::") == std::string::npos);
        if ( auto nx = N(x) )
            _id += *nx;
        else
            _id += x;
    }

    Views* _cachedViews() const noexcept {
        if ( _views )
            return _views.get();

        _views = std::make_unique<Views>();

        size_t ns_end = std::string::npos;
        _views->path.clear();

        for ( size_t i = 0; i < _id.size(); /* empty */ ) {
            if ( auto p = _id.find("::", i); p != std::string::npos ) {
                _views->path.emplace_back(std::string_view(_id).substr(i, p - i));
                i = p + 2;
                ns_end = p;
            }
            else {
                _views->path.emplace_back(std::string_view(_id).substr(i));
                break;
            }
        }

        if ( ns_end != std::string::npos ) {
            _views->namespace_ = std::string_view(_id).substr(0, ns_end);
            _views->local = std::string_view(_id).substr(ns_end + 2);
        }
        else {
            _views->namespace_ = {};
            _views->local = std::string_view(_id);
        }

        return _views.get();
    }

    std::string _id;                       // normalized full-path ID
    mutable std::unique_ptr<Views> _views; // allocated on demand first time view information is needed
};

} // namespace hilti::detail
