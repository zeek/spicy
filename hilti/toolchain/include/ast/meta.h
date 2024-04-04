// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/rt/util.h>

#include <hilti/ast/location.h>

namespace hilti {
class Meta;
}

template<>
struct std::hash<hilti::Meta> {
    size_t operator()(const hilti::Meta& meta) const;
};

namespace hilti {

/**
 * Meta information associated with AST nodes. The meta data can include a
 * source code location, source code comments, and an error message.
 */
class Meta {
public:
    /** List of comments. */
    using Comments = std::vector<std::string>;

    Meta(Location location, Comments comments = {}) : _comments(std::move(comments)) {
        setLocation(std::move(location));
    }

    /** Constructor that leaves location unset. */
    Meta(Comments comments = {}) : _comments(std::move(comments)) {}

    Meta(const Meta&) = default;
    Meta(Meta&&) = default;

    const Comments& comments() const { return _comments; }
    const Location& location() const {
        static Location null;
        return _location ? *_location : null;
    }

    void setLocation(Location l) { _location = std::move(l); }
    void setComments(Comments c) { _comments = std::move(c); }

    /**
     * Returns true if the location does not equal a default constructed
     * instance.
     */
    explicit operator bool() const { return _location || _comments.size(); }

    Meta& operator=(const Meta&) = default;
    Meta& operator=(Meta&&) = default;

    friend bool operator==(const Meta& a, const Meta& b) {
        return a._location == b._location && a._comments == b._comments;
    }

    friend bool operator!=(const Meta& a, const Meta& b) { return ! (a == b); }

    /**
     * Returns pointer to a globally shared/cached version of a meta instance.
     * The returned pointer can be used instead of the Meta instance passed in,
     * and it guaranteed to remain valid for the entire lifetime of the
     * program.
     */
    static const Meta* get(Meta m) { return &*_cache.emplace(std::move(m)).first; }

private:
    std::optional<Location> _location;
    Comments _comments;

    static std::unordered_set<Meta> _cache; // global cache of meta instances
};

} // namespace hilti

inline size_t std::hash<hilti::Meta>::operator()(const hilti::Meta& meta) const {
    size_t h = 0;
    for ( const auto& c : meta.comments() )
        h = hilti::rt::hashCombine(h, std::hash<std::string>()(c));

    return hilti::rt::hashCombine(h, std::hash<std::optional<hilti::Location>>()(meta.location()));
}
