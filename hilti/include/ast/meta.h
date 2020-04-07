// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/ast/location.h>

namespace hilti {

/**
 * Meta information associated with AST nodes. The meta data can include a
 * source code location, source code comments, and an error message.
 */
class Meta {
public:
    /** List of comments. */
    using Comments = std::vector<std::string>;

    Meta(Location location, Comments comments = {}) : _location(std::move(location)), _comments(std::move(comments)) {}

    /** Constructor that leaves location unset. */
    Meta(Comments comments = {}) : _comments(std::move(comments)) {}

    const Location& location() const { return _location; }
    const Comments& comments() const { return _comments; }

    void setLocation(const Location& l) { _location = l; }
    void setComments(const Comments& c) { _comments = c; }

    /**
     * Returns true if the location does not equal a default constructed
     * instance.
     */
    explicit operator bool() const { return _location || _comments.size(); }

private:
    Location _location;
    Comments _comments;
};

} // namespace hilti
