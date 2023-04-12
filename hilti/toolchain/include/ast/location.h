// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <string>
#include <utility>

#include <hilti/rt/filesystem.h>

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
     * @param from_line first line number of the described range; -1 if not available.
     * @param to_line last line number of the described range; -1 if not available.
     * @param from_character first character number of the described range; -1 if not available.
     * @param to_character first character number of the described range; -1 if not available.
     */
    Location(hilti::rt::filesystem::path file = "", int from_line = -1, int to_line = -1, int from_character = -1,
             int to_character = -1)
        : _file(std::move(file)),
          _from_line(from_line),
          _to_line(to_line),
          _from_character(from_character),
          _to_character(to_character) {}

    Location(const Location&) = default;
    Location(Location&&) = default;
    Location& operator=(const Location&) = default;
    Location& operator=(Location&&) = default;
    ~Location() = default;

    auto file() const { return _file.generic_string(); }
    auto from() const { return _from_line; }
    auto to() const { return _to_line; }

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
        return std::tie(_file, _from_line, _from_character, _to_line, _to_character) <
               std::tie(other._file, other._from_line, other._from_character, other._to_line, other._to_character);
    }

    bool operator==(const Location& other) const {
        return std::tie(_file, _from_line, _from_character, _to_line, _to_character) ==
               std::tie(other._file, other._from_line, other._from_character, other._to_line, other._to_character);
    }

private:
    hilti::rt::filesystem::path _file;
    int _from_line = -1;
    int _to_line = -1;

    int _from_character = -1;
    int _to_character = -1;

    friend struct std::hash<Location>;
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

namespace std {
template<>
struct hash<hilti::Location> {
    size_t operator()(const hilti::Location& x) const {
        return hilti::rt::hashCombine(std::hash<std::string>()(x._file), x._from_line, x._to_line, x._from_character,
                                      x._to_character);
    }
};
} // namespace std
