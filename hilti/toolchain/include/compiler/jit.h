// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/library.h>

#include <hilti/base/util.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/cxx/unit.h>

#include <tiny-process-library/process.hpp>

namespace hilti {

namespace logging::debug {
inline const DebugStream Jit("jit");
} // namespace logging::debug

namespace detail::jit {
class Cxx;
} // namespace detail::jit

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
 */
class JIT {
public:
    /**
     * @param context compiler context to use
     * @param dump_code if true, save all C++ code into files `dbg.*` for debugging
     */
    explicit JIT(std::shared_ptr<Context> context, bool dump_code = false);
    ~JIT();

    JIT() = delete;
    JIT(const JIT&) = delete;
    JIT(JIT&&) noexcept = delete;
    JIT& operator=(const JIT&) = delete;
    JIT& operator=(JIT&&) noexcept = delete;

    /**
     * Schedules C++ for just-in-time compilation. This must be called only
     * before `jit()`.
     *
     * @param d C++ code
     */
    void add(CxxCode d) { _codes.push_back(std::move(d)); }

    /**
     * Schedules C++ for just-in-time compilation. This must be called only
     * before `compile()`.
     *
     * @param d file to read C++ code from
     */
    void add(const hilti::rt::filesystem::path& p) { _files.push_back(p); }

    /**
     * Returns true if any source files have been added that need to be
     * compiled.
     */
    bool hasInputs() { return _codes.size() || _files.size(); }

    /**
     * Compiles and links all scheduled C++ code into a shared library.
     *
     * @return the compiled library, which will be ready for loading.
     */
    Result<std::shared_ptr<const Library>> build();

    /** Returns the compiler context in use. */
    auto context() const { return _context; }

    /** Returns the compiler options in use. */
    auto options() const { return _context->options(); }

private:
    // Check if we have a working compiler.
    hilti::Result<Nothing> _checkCompiler();

    // Prepare for compilation.
    hilti::Result<Nothing> _initialize();

    // Compile C++ to object files.
    hilti::Result<Nothing> _compile();

    // Link object files into shared library.
    hilti::Result<std::shared_ptr<const Library>> _link();

    // Clean up after compilation.
    void _finish();

    using JobID = uint64_t;
    Result<JobID> _spawnJob(hilti::rt::filesystem::path cmd, std::vector<std::string> args);
    Result<Nothing> _waitForJob(JobID id);
    Result<Nothing> _waitForJobs();

    hilti::rt::filesystem::path _makeTmp(std::string base, std::string ext);

    std::shared_ptr<Context> _context; // global context for options
    bool _dump_code;                   // save all C++ code for debugging

    std::vector<hilti::rt::filesystem::path> _files; // all added source files
    std::vector<CxxCode> _codes;                     // all C++ code units to be compiled
    std::vector<hilti::rt::filesystem::path> _objects;

    hilti::rt::filesystem::path _tmpdir;

    struct Job {
        std::unique_ptr<TinyProcessLib::Process> process;
        std::string stdout_;
        std::string stderr_;
    };

    JobID _job_counter = 0;
    std::map<JobID, Job> _jobs;

    std::map<std::string, unsigned int> _tmp_counters;
};

} // namespace hilti
