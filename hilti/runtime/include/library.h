// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <hilti/rt/filesystem.h>
#include <hilti/rt/result.h>
#include <hilti/rt/util.h>

namespace hilti::rt::library {

/**
 * Version information that's embedded as JSON into HLTO libraries to record
 * the HILTI version they were compile with.
 */
struct Version {
    std::string magic;      /**< magic string for identification */
    uint64_t hilti_version; /**< HILTI project version */
    bool debug;             /**< true if compiled in debug mode */

    hilti::rt::filesystem::path path; /**< path to file that library was loaded from; not embedded into JSON, but filled
                                   in by `Library::open()` */

    /** Converts the instances into a JSON string. */
    std::string toJSON() const;

    /**
     * Parses a JSON representation of an instance.
     *
     * @return a Version or an error if parsing of JSON failed
     */
    static hilti::rt::Result<Version> fromJSON(const std::string& json);

    /**
     * Checks the version for compatibility with the current runtime system.
     * Prints out warnings on mismatches, but doesn't abort.
     */
    void checkCompatibility() const;

    friend bool operator==(const Version& a, const Version& b) {
        return a.magic == b.magic && a.hilti_version == b.hilti_version && a.debug == b.debug;
    }

    friend bool operator!=(const Version& a, const Version& b) { return ! (a == b); }
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
public:
    /**
     * Makes a library available for opening.
     *
     * @param path full path to the library file
     * @throws *std::runtime_error* if library does not exist, or any other I/O operation failed
     */
    Library(const hilti::rt::filesystem::path& path);
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
     * @param path the path where this library should be stored
     * @return nothing or an error
     */
    hilti::rt::Result<Nothing> save(const hilti::rt::filesystem::path& path) const;

    // Gets a symbol from the library.
    //
    // @param name name of the symbol
    // @return a valid pointer to the symbol or an error
    hilti::rt::Result<void*> symbol(const char* name) const;

    /*
     * Remove the file corresponding to this library without unloading it.
     *
     * @return nothing or an error
     */
    hilti::rt::Result<Nothing> remove() const;

    /**
     * Sets the passed linker scope.
     *
     * If a library is currently being loaded through `open()`, the
     * scope is (stable) hash of that library's absolute path. If we're outside
     * of library loading, this returns a scope that's guaranteed to be unique
     * across all calls to this method.
     *
     * This method is meant to be called only from the generated linker code to
     * set a module's global scope variable. Its semantics are tailored to that
     * use case.
     *
     * @param a non-null pointer to the scope to update.
     */
    static void setScope(uint64_t* scope);

private:
    hilti::rt::filesystem::path _path; // Absolute path to the physical file wrapped by this instance.
    mutable void* _handle = nullptr;   // Handle to the library.

    static std::optional<hilti::rt::filesystem::path>
        _current_path; // absolute path to library currently being loaded, if any
};

} // namespace hilti::rt
