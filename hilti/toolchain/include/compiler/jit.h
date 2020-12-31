// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/library.h>

#include <hilti/base/util.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/cxx/unit.h>

namespace hilti {

namespace logging::debug {
inline const DebugStream Jit("jit");
} // namespace logging::debug

namespace detail::jit {
class Cxx;
} // namespace detail

/** Container for C++ code compiled from a HILTI source file */
class CxxCode {
public:
    /**
     * Reads C++ code from a file.
     *
     * @param path file to read
     */
    CxxCode(const hilti::rt::filesystem::path& path) { load(path); }

    /**
     * Reads C++ code from an input stream.
     *
     * @param id name to associate with the input for logging and error messages.
     * @param code stream to read from
     */
    CxxCode(const std::string& id, std::istream& code) { load(id, code); }

    /**
     * Initializes code instance from in-memory compiler output. For internal use.
     *
     * @param u unit to initialize code instance from
     */
    explicit CxxCode(const detail::cxx::Unit& u);


    /**
     * Saves C++ code into a file.
     *
     * @param p file to write to
     * @return true if succesful
     */
    bool save(const hilti::rt::filesystem::path& p) const;

    /**
     * Writes C++ code into an output stream.
     *
     * @param out stream to write to
     * @return true if succesful
     */
    bool save(std::ostream& out) const;

    /** Returns C++ code as a string. */
    auto code() const { return _code; }

    /** Returns true if this instance has been initialized with any C++ code. */
    auto isLoaded() const { return _code.has_value(); }

    /**
     * Returns a name associated with the instance's C++ code. If the code
     * has been read from a file, that's the path; otherwise the ID specifed
     * when initialized.
     */
    const std::string& id() const { return _id; }

protected:
    /**
     * Loads C++ code from a file.
     *
     * @param path file to read from
     * @return true if succesful
     */
    bool load(const hilti::rt::filesystem::path& path);

    /**
     * Loads C++ code from an input stream.
     *
     * @param id name to associate with the input for logging and error messages.
     * @param path stream to read from
     * @return true if succesful
     */
    bool load(const std::string& id, std::istream& in);

private:
    std::string _id;
    std::optional<std::string> _code;
};

using hilti::rt::Library;

/**
 * Just-in-time compiler.
 *
 * The class provides the entry point for compiling and executing C++ code
 * just in time.
 *
 * @note The compiler can be used only if the global configuration indicates
 * that HILTI has been compiled with JIT support.
 *
 * @todo The error handling in this class isn't great. Most methods just
 * return booleans, and otherwise report through the globa `Logger`; should
 * switch that to `Result<>`. Worse, the actual compilation/linking outpus
 * diagnostics directly to stderr currently.
 *
 * @todo Our JITing doesn't support C++ code with global
 * intialization/cleanup code currently (like global ctors/dtors). It would
 * probably be tricky to add that.
 */
class JIT {
public:
    /**
     * @param context compiler context to use
     */
    explicit JIT(std::shared_ptr<Context> context);
    ~JIT();

    JIT() = delete;
    JIT(const JIT&) = delete;
    JIT(JIT&&) noexcept = delete;
    JIT& operator=(const JIT&) = delete;
    JIT& operator=(JIT&&) noexcept = delete;

    /**
     * Schedules C++ for just-in-time compilation. This must be called only
     * before `compile()`.
     *
     * @param d C++ code
     */
    void add(CxxCode d) { _codes.push_back(std::move(d)); }

    /**
     * Adds a precompiled shared library. This must be called only before
     * `jit()`.
     *
     * @param library precompiled shared library
     * @return version information extracted from loaded library
     */
    Result<hilti::rt::library::Version> add(Library library) { return library.open(); }

    /**
     * Activates saving any emitted code to disk for debugging purposes.
     * It will land in files ``dbg.*``.
     */
    void setDumpCode();

    /**
     * Schedules C++ for just-in-time compilation. This must be called only
     * before `compile()`.
     *
     * @param d file to read C++ code from
     */
    void add(const hilti::rt::filesystem::path& p) { _files.push_back(p); }

    /**
     * Compiles all added C++ source files into internal bitcode.
     *
     * HILTI-level errors will be logged through the global `Logger`. If the
     * C++ code contains any errors, that will currently be reported directly
     * to stderr.
     *
     * @return true if all files have been succesfully compiled
     */
    bool compile();

    /**
     * Compiles the linked bitcode into native executable code and makes it
     * available inside the current process. This must be called opnly after
     * `link()`
     *
     * Errors will be logged through the global `Logger`
     *
     * @return succes if the bitcode has been succesfully JITed, otherwise an appropiate error
     */
    Result<Nothing> jit();

    /**
     * Returns already JITed code as a shared library that can be cached.
     * This must be called only after `jit()` has been called and succeeded.
     */
    Result<std::shared_ptr<const Library>> retrieveLibrary() const;

    /**
     * Returns true if any source files have been added that need to be
     * compiled. If this returns false, its safe to skip calling `compile()`
     * (though still doing so won't hurt).
     */
    bool needsCompile() { return _codes.size() || _files.size(); }

    /** Returns the compiler context in use. */
    auto context() const { return _context; }

    /** Returns the compiler options in use. */
    auto options() const { return _context->options(); }

    /**
     * Returns a string identifying the underlying compiler used for JIT
     * compilation.
     */
    static std::string compilerVersion();

private:
    std::shared_ptr<Context> _context;
    std::vector<hilti::rt::filesystem::path> _files; // all added source files
    std::vector<CxxCode> _codes;                     // all C++ code units to be compiled
    std::vector<Library> _libraries;                 // all precomiled modules we know about
    std::unique_ptr<detail::jit::Cxx> _jit;          // JIT backend
};

} // namespace hilti
