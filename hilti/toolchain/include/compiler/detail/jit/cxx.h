// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>

#include <hilti/base/result.h>
#include <hilti/compiler/jit.h>

namespace hilti::detail::jit {

/** JIT implementation using the host's C++ compiler as the backend. */
class Cxx {
public:
    /**
     * Constructor
     *
     * @param context global context to pull settings from
     */
    Cxx(std::shared_ptr<Context> context);
    ~Cxx();

    Cxx(const Cxx&) = delete;
    Cxx(Cxx&&) noexcept = delete;
    Cxx& operator=(const Cxx&) = delete;
    Cxx& operator=(Cxx&&) noexcept = delete;

    /**
     * Compiles one C++ module into object code.
     *
     * This must be called after ``init()`` and before ``jit()``.
     *
     * @param code in-memory representation of the C++ code to compile
     * @return true if compilation succeeded; the object code will then have
     * been recorded internally for later linking
     */
    bool compile(const CxxCode& code);

    /**
     * Compiles one C++ module into object code.
     *
     * This must be called after ``init()`` and before ``jit()``.
     *
     * @param p path to read C++ code from
     * @return true if compilation succeeded; the object code will then have
     * been recorded internally for later linking
     */
    bool compile(const hilti::rt::filesystem::path& p);

    /*
     * Links all modules compiled so far into a shared library, and then loads
     * the library into the current process.
     *
     * This must be called after ``init()`` and after all desired code has
     * been added.
     *
     * @return success if linking and loading was successful, an appropriate
     * error otherwise.
     */
    Result<Nothing> jit();

    /**
     * Retrieves the final shared library created by `jit()`..
     *
     * This must be called only after ``jit()`` has succeeded.
     *
     * @returns shared library, or a null pointer if `jit()` has not completed
     * successfully yet.
     */
    std::shared_ptr<const Library> retrieveLibrary() const;

    /**
     * Activates saving any emitted code to disk for debugging purposes. The
     * code will land in files ``dbg.*`` inside the current directory.
     */
    void setDumpCode();

    /**
     * Returns a string describing the compiler in use, including its specific
     * version.
     */
    static std::string compilerVersion();

private:
};

} // namespace hilti::detail
