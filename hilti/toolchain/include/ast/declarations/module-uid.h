// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cinttypes>
#include <string>
#include <unordered_map>
#include <utility>

#include <hilti/rt/filesystem.h>

#include <hilti/ast/id.h>

namespace hilti::declaration::module {

/**
 * Globally unique identifier for a specific module that can be used to refer
 * to it unambiguously.
 */
struct UID {
    ID id;     /**< module name */
    ID unique; /**< globally uniqued name for the module */
    hilti::rt::filesystem::path
        path; /**< path to module's source code on disk; will be set to a unique place-holder if no file exists */
    hilti::rt::filesystem::path parse_extension; /**< language extension determining how to *parse* this module, usually
                                                    derive from file name */
    hilti::rt::filesystem::path
        process_extension; /**< language extension determining how to process this module *after* parsing */
    bool in_memory;        /**< true if the module does not correspond to a file on disk */

    /**
     * Constructor creating a UID from a module name and a path to its source
     * code. Extensions are derived from the
     * path.
     *
     * @param id module name
     * @param path path to module's source code file
     **/
    UID(ID id, const hilti::rt::filesystem::path& path)
        : id(std::move(id)),
          unique(_makeUnique(this->id)),
          path(util::normalizePath(path)),
          parse_extension(path.extension()),
          process_extension(path.extension()),
          in_memory(false) {
        assert(this->id && ! path.empty());
    }

    /**
     * Constructor creating a UID from a module name and explicitly given
     * extensions. Internally, we create a unique path as well, just so that
     * one can depend on always having one.
     *
     * @param id module name
     * @param parse_extension language extension determining how to *parse* this module
     * @param process_extension language extension determining how to process this module *after* parsing
     **/
    UID(const ID& id, const hilti::rt::filesystem::path& parse_extension,
        const hilti::rt::filesystem::path& process_extension)
        : id(id),
          unique(_makeUnique(this->id)),
          parse_extension(parse_extension),
          process_extension(process_extension),
          in_memory(true) {
        assert(this->id && ! parse_extension.empty() && ! process_extension.empty());
        //  just make up a path
        path = util::fmt("/tmp/hilti/%s.%" PRIu64 ".%s.%s", id, ++_no_file_counter, process_extension, parse_extension);
    }

    UID(const UID& other) = default;
    UID(UID&& other) = default;
    ~UID() = default;

    /** Hashes the UID. */
    size_t hash() const {
        return rt::hashCombine(std::hash<std::string>{}(id.str()), std::hash<std::string>{}(path.native()),
                               std::hash<std::string>{}(parse_extension.native()),
                               std::hash<std::string>{}(process_extension.native()));
    }

    UID& operator=(const UID& other) = default;
    UID& operator=(UID&& other) = default;

    bool operator==(const UID& other) const {
        return id == other.id && path == other.path && parse_extension == other.parse_extension &&
               process_extension == other.process_extension;
    }

    bool operator!=(const UID& other) const { return ! (*this == other); }
    bool operator<(const UID& other) const {
        return std::make_tuple(id, path, parse_extension, process_extension) <
               std::make_tuple(other.id, other.path, other.parse_extension, other.process_extension);
    }

    /** Returns the module's globally uniqued name. */
    std::string str() const { return unique; }

    /** Forwards to `str()`. */
    operator std::string() const { return str(); }

    /** Returns false if the UID is default-constructed. */
    explicit operator bool() const { return ! id.empty(); }

private:
    ID _makeUnique(const ID& id) const {
        auto& x = _id_to_counter[id];
        return ++x > 1 ? ID(util::fmt("%s_%" PRIu64, id, x)) : id;
    }

    inline static uint64_t _no_file_counter = 0; // global counter for creating unique paths for modules without any
    inline static std::unordered_map<std::string, uint64_t>
        _id_to_counter{}; // global counter for creating unique modules names
};

inline std::ostream& operator<<(std::ostream& stream, const UID& uid) { return stream << uid.str(); }

} // namespace hilti::declaration::module

namespace std {
template<>
struct hash<hilti::declaration::module::UID> {
    size_t operator()(const hilti::declaration::module::UID& x) const { return x.hash(); }
};
} // namespace std
