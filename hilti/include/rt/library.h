// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/result.h>
#include <hilti/rt/util.h>

namespace hilti::rt::library {

/**
 * Version information that's embedded as JSON into HLTO libraries to record
 * the HILTI version they were compile with.
 */
struct Version {
    std::string magic; /**< magic string for identification */
    int hilti_version; /**< HILTI project version */
    double created;    /**< time library was compiled in seconds since epoch */
    bool debug;        /**< true if compiled in debug mode */
    bool optimize;     /**< true if compiled with optimizations enabled */

    std::filesystem::path path; /**< path to file that library was loaded from; not embedded into JSON, but filled in by
                                   `Library::open()` */

    /** Converts the instances into a JSON string. */
    std::string toJSON() const;

    /**
     * Parses a JSON representation of an instance.
     *
     * @return error if parsing of JSON failed
     */
    hilti::rt::Result<Nothing> fromJSON(const std::string& json);

    /**
     * Checks the version for compatibility with the current runtime system.
     * Prints out warnings on mismatches, but doesn't abort.
     */
    void checkCompatibility() const;
};

} // namespace hilti::rt::library

namespace hilti::rt {

/**
 * Container for storing code compiled into a native shared library.
 *
 * This class loads the underlying library it wraps into its internal store on
 * construction and subsequently does not depend on it anymore.
 */
class Library {
    using Nothing = hilti::rt::Nothing;

public:
    /**
     * Makes a library available for opening.
     *
     * @param path full path to the library file
     * @throws *std::runtime_error* if library does not exist, or any other I/O operation failed
     */
    Library(const std::filesystem::path& path);
    ~Library();

    // Since this library has exclusive ownership of some path it cannot be copied.
    Library(const Library&) = delete;
    Library& operator=(const Library&) = delete;

    Library(Library&&) = default;
    Library& operator=(Library&&) = default;

    /**
     * Load the library into the current process
     *
     * @return version information extracted from loaded library
     **/
    hilti::rt::Result<hilti::rt::library::Version> open() const;

    /**
     * Save this library under a different path.
     *
     * @parm path the path where this library should be stored
     * @return nothing or an error
     */
    hilti::rt::Result<Nothing> save(const std::filesystem::path& path) const;

private:
    std::filesystem::path _path;      // Absolute path to the physical file wrapped by this instance.
    std::filesystem::path _orig_path; // Original path as passed into the constructor.
};

} // namespace hilti::rt
