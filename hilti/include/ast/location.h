// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/base/util.h>

namespace hilti {

/**
 * Source code locations associated with AST nodes.
 */
class Location {
public:
    /**
     * Constructor. If all arguments are left at their default, the instance
     * will match `location::None`.
     *
     * @param file file name/path associated with the location; empty if unknown.
     * @param from first line number of the described range; -1 if not availabl.
     * @param to last line number of the described range; -1 if not availabl.
     */
    Location(std::filesystem::path file = "", int from = -1, int to = -1)
        : _file(std::move(file)), _from(from), _to(to) {}

    Location(const Location&) = default;
    Location(Location&&) = default;
    Location& operator=(const Location&) = default;
    Location& operator=(Location&&) = default;
    ~Location() = default;

    auto file() const { return _file.generic_string(); }
    auto from() const { return _from; }
    auto to() const { return _to; }

    /**
     * Returns a string representation of the location.
     *
     * @param no_path if true, do not include the file
     */
    std::string render(bool no_path = false) const;

    /**
     * Returns true if the location is set. A location is unset if it equals
     * `location::None` (which a default constructed location will)..
     */
    explicit operator bool() const;

    /** Forwards to `render()`. */
    operator std::string() const { return render(); }

    bool operator<(const Location& other) const {
        return std::tie(_file, _from, _to) < std::tie(other._file, other._from, other._to);
    }

private:
    std::filesystem::path _file;
    int _from;
    int _to;
};

/** Forwards to `Location::render()`. */
inline auto to_string(const Location& l) { return l.render(); }

/** Forwards to `Location::render()`. */
inline std::ostream& operator<<(std::ostream& out, const Location& l) {
    out << l.render();
    return out;
}

namespace location {
/** Sentinel value indicating that no location information is available. */
extern const Location None;
} // namespace location

} // namespace hilti
