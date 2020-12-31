// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <iosfwd>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <tiny-process-library/process.hpp>

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
    bool compile(const hilti::rt::filesystem::path& path);

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

    const auto& options() { return _context->options(); }

    /**
     * Returns a string describing the compiler in use, including its specific
     * version.
     */
    static std::string compilerVersion();

private:
    using JobID = uint64_t;

    Result<JobID> _spawnJob(hilti::rt::filesystem::path cmd, std::vector<std::string> args);
    Result<Nothing> _waitForJob(JobID id);
    Result<Nothing> _waitForJobs();

    void _terminateAll();
    hilti::rt::filesystem::path _makeTmp(std::string base, std::string ext);

    std::shared_ptr<Context> _context;
    hilti::rt::filesystem::path _workdir;

    struct Job {
        std::unique_ptr<TinyProcessLib::Process> process;
        std::string stdout;
        std::string stderr;
    };

    std::map<JobID, Job> _jobs;
    std::vector<hilti::rt::filesystem::path> _objects;
    std::shared_ptr<const Library> _library;

    JobID _job_counter = 0;
    std::map<std::string, unsigned int> _tmp_counters;
};

} // namespace hilti::detail::jit
