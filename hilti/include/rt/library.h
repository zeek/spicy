// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/result.h>
#include <hilti/rt/util.h>

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
     * @return nothing or an error
     * */
    hilti::rt::Result<Nothing> open() const;

    /**
     * Save this library under a different path.
     *
     * @parm path the path where this library should be stored
     * @return nothing or an error
     */
    hilti::rt::Result<Nothing> save(const std::filesystem::path& path) const;

private:
    std::filesystem::path _path; // Absolute path to the physical file wrapped by this instance.
};

} // namespace hilti::rt
