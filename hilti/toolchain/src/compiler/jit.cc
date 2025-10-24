// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <sys/resource.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <thread>
#include <utility>
#include <vector>

#include <hilti/rt/init.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

#include <hilti/autogen/config.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/cxx/unit.h>
#include <hilti/compiler/jit.h>

// GCC-13 warns about code in reproc++. This is fixed upstream with
// DaanDeMeyer/reproc@0b23d88894ccedde04537fa23ea55cb2f8365342, but that patch
// has not landed in a release yet. Disable the warning if the compiler knows
// about it.
//
// TODO(bbannier): Drop this once reproc puts out a release officially supporting gcc-13.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#pragma GCC diagnostic ignored "-Wchanges-meaning"
#include <reproc++/drain.hpp>
#include <reproc++/reproc.hpp>
#include <reproc++/run.hpp>
#pragma GCC diagnostic pop

using namespace hilti;

namespace {

const auto UserDiagnosticsFile = rt::filesystem::path("hilti-jit-error.log");

hilti::rt::filesystem::path save(const CxxCode& code, const hilti::rt::filesystem::path& id, std::size_t hash) {
    const auto cc_hash = code.hash();

    // Create a random temporary file owned only by us so we are not racing
    // with other processes attempting to create the same output file.
    //
    // We create this file in the same location as the final file so we can
    // perform an atomic move below.
    std::string cc0 = hilti::rt::filesystem::temp_directory_path() / "spicy-jit-cc-XXXXXXXXXXXX";
    if ( auto fd = ::mkstemp(cc0.data()); fd == -1 )
        rt::fatalError(util::fmt("could not create temporary file: %s", strerror(errno)));
    else
        ::close(fd);

    auto cc1 = hilti::rt::filesystem::temp_directory_path() /
               util::fmt("%s_%" PRIx64 "-%" PRIx64 ".cc", id.stem().c_str(), hash, cc_hash);

    std::ofstream out(cc0);

    if ( ! out )
        rt::fatalError(util::fmt("could not open file %s for writing", cc1));

    if ( const auto& content = code.code() )
        out << *content;

    out.close();
    if ( out.fail() )
        rt::fatalError(util::fmt("could not write to temporary file %s", cc1));

    // Atomically move the temporary file to its final location. With that
    // even with concurrent saves to the same final path other processes should
    // always see a consistent version of the contents of that file.
    std::error_code ec;
    hilti::rt::filesystem::rename(cc0, cc1, ec);
    if ( ec )
        rt::fatalError(util::fmt("could not move file %s to final location %s: %s", cc0, cc1, ec.message()));

    return cc1;
}

// An RAII helper which removes all files added to it on destruction.
class FileGuard {
public:
    void add(hilti::rt::filesystem::path path) { _paths.emplace_back(std::move(path)); }

    ~FileGuard() {
        for ( const auto& cc : _paths ) {
            HILTI_DEBUG(logging::debug::Jit, util::fmt("removing temporary file %s", cc));

            std::error_code ec;
            hilti::rt::filesystem::remove(cc, ec);

            if ( ec )
                HILTI_DEBUG(logging::debug::Jit, util::fmt("could not remove temporary file %s: %s", cc, ec.message()));
        }
    }

private:
    std::vector<hilti::rt::filesystem::path> _paths;
};

} // namespace

namespace hilti::logging::debug {
inline const DebugStream Driver("driver");
} // namespace hilti::logging::debug

CxxCode::CxxCode(const detail::cxx::Unit& u) {
    std::stringstream buffer;
    u.print(buffer);
    load(u.cxxModuleID(), buffer);
}

bool CxxCode::load(const hilti::rt::filesystem::path& path) {
    std::ifstream in;
    in.open(path);

    if ( ! in )
        return false;

    if ( ! load(path, in) )
        return false;

    _id = path;
    return true;
}

bool CxxCode::load(const std::string& id, std::istream& in) {
    std::string code{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};

    if ( in.fail() )
        return false;

    _id = id;
    _code = std::move(code);
    _hash = std::hash<std::string>{}(*_code);
    return true;
}

bool CxxCode::save(const hilti::rt::filesystem::path& p) const {
    if ( ! _code )
        return false;

    std::ofstream out(p);

    if ( ! out )
        return false;

    out << *_code;
    out.close();
    return ! out.fail();
}

bool CxxCode::save(std::ostream& out) const {
    if ( ! _code )
        return false;

    out << *_code;
    return ! out.fail();
}

JIT::JIT(const std::shared_ptr<Context>& context, bool dump_code)
    : _context(context),
      _dump_code(dump_code),
      _hash(std::hash<std::string>{}(hilti::rt::filesystem::current_path().string())) {}

JIT::~JIT() {
    try {
        _finish();
    } catch ( ... ) {
        util::cannotBeReached();
    }
}

hilti::Result<std::shared_ptr<const Library>> JIT::build() {
    auto _guard = util::scope_exit([&]() {
        // Point out user diagnostics file if it exists.
        if ( ! hilti::rt::filesystem::exists(UserDiagnosticsFile) )
            return;

        std::cerr << util::fmt(R"(
=== Uh oh ... C++ compilation failed ===

This is unexpected and should not happen. Please help us fix the issue
by opening a ticket at https://github.com/zeek/spicy/issues/new.

Please include the content of the following file with your report:

  %s

That file contains diagnostics from the C++ compiler. Please also
include your Spicy code that triggered this error, ideally reduced to
a small snippet still exhibiting the issue if you can.

===

)",
                               rt::filesystem::absolute(UserDiagnosticsFile));

        if ( auto* show_output = getenv("HILTI_JIT_SHOW_CXX_OUTPUT"); show_output && *show_output ) {
            // Also print the output of the C++ compiler to stderr.
            std::ifstream in(UserDiagnosticsFile);
            if ( in ) {
                std::cerr << "### Begin of " << UserDiagnosticsFile << " ###\n\n";

                std::string line;
                while ( std::getline(in, line) )
                    std::cerr << line << '\n';

                std::cerr << "\n### End of " << UserDiagnosticsFile << " ###\n\n";
            }
        }
    });

    util::timing::Collector _("hilti/jit");

    if ( auto rc = _checkCompiler(); ! rc )
        return rc.error();

    if ( auto rc = _compile(); ! rc )
        return rc.error();

    auto library = _link();
    _finish(); // clean up no matter if successful
    return library;
}

hilti::Result<Nothing> JIT::_checkCompiler() {
    const auto& cxx = hilti::configuration().cxx;

    // We ignore the output, just see if running the compiler works. `-dumpversion`
    // works with both GCC and clang, but unlikely to be supported by something
    // other than a compiler.
    if ( auto rc = _runner._scheduleJob(cxx, {"-dumpversion"}); ! rc )
        return result::Error(util::fmt("C++ compiler not available or not functioning (looking for %s)", cxx),
                             rc.error().context());

    if ( auto rc = _runner._waitForJobs(); ! rc )
        return result::Error(util::fmt("C++ compiler not available or not functioning (looking for %s)", cxx),
                             rc.error().context());

    return Nothing();
}

JIT::Job::~Job() { hilti::rt::filesystem::remove(output); }

void JIT::JobRunner::finish() {
    for ( auto&& [id, job] : jobs ) {
        auto [status, ec] = job.process->stop(reproc::stop_actions{
            .first = {.action = reproc::stop::terminate, .timeout = reproc::milliseconds(1000)},
            .second = {.action = reproc::stop::kill, .timeout = reproc::milliseconds::max()},
        });

        if ( ec )
            HILTI_DEBUG(logging::debug::Jit, util::fmt("failed to stop job: %s", ec.message()));

        // Since we terminated the process forcibly, which if the process was still running probably
        // triggered a non-zero exist status, we ignore the status returned from `stop`.
    }

    jobs.clear();
}

void JIT::_finish() {
    if ( ! options().keep_tmps )
        for ( const auto& object : _objects ) {
            HILTI_DEBUG(logging::debug::Jit, util::fmt("removing temporary file %s", object));

            std::error_code ec;
            hilti::rt::filesystem::remove(object, ec);

            if ( ec )
                HILTI_DEBUG(logging::debug::Jit, util::fmt("could not remove temporary file %s", object));
        }

    _objects.clear();

    _runner.finish();
}

hilti::Result<Nothing> JIT::_compile() {
    util::timing::Collector _("hilti/jit/compile");

    if ( ! hasInputs() )
        return Nothing();

    auto cc_files = _files;

    // Remember generated files and remove them on all exit paths.
    bool keep_tmps = options().keep_tmps;
    FileGuard cc_files_generated;

    // Write all in-memory code into temporary files.
    for ( const auto& code : _codes ) {
        std::string id = hilti::rt::filesystem::path(code.id());
        if ( id.empty() )
            id = "code"; // dummy name

        auto cc = save(code, id, _hash);

        if ( _dump_code ) {
            // Logging to driver because that's where all the other "saving to ..." messages go.
            auto dbg = util::fmt("dbg.%s", cc.filename().native());
            HILTI_DEBUG(logging::debug::Driver, util::fmt("saving code for %s to %s", id, dbg));

            std::error_code ec;
            hilti::rt::filesystem::copy(cc, dbg, hilti::rt::filesystem::copy_options::overwrite_existing,
                                        ec); // will save into current directory; ignore errors
        }

        cc_files.push_back(cc);
        if ( ! keep_tmps )
            cc_files_generated.add(std::move(cc));
    }

    // Compile all C++ files.
    std::vector<result::Error> errors;
    for ( const auto& path : cc_files ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("compiling %s", path.filename().native()));

        std::vector<std::string> args = {"-c"};

        if ( options().debug )
            args = hilti::util::concat(args, hilti::configuration().hlto_cxx_flags_debug);
        else
            args = hilti::util::concat(args, hilti::configuration().hlto_cxx_flags_release);

        // For debug output on compilation:
        // args.push_back("-v");
        // args.push_back("-###");

        for ( const auto& i : options().cxx_include_paths ) {
            args.emplace_back("-I");
            args.push_back(i);
        }

        if ( auto path = hilti::rt::getenv("HILTI_CXX_INCLUDE_DIRS") ) {
            for ( auto&& dir : hilti::rt::split(*path, ":") ) {
                if ( ! dir.empty() ) {
                    args.insert(args.begin(), {"-I", std::string(dir)});
                }
            }
        }

        if ( auto flags_ = hilti::rt::getenv("HILTI_CXX_FLAGS") ) {
            if ( auto flags = util::splitShellUnsafe(*flags_) )
                args.insert(args.end(), std::make_move_iterator(flags->begin()), std::make_move_iterator(flags->end()));
            else
                return {util::fmt("invalid HILTI_CXX_FLAGS '%s': %s", *flags_, flags.error().description())};
        }

        // We explicitly create the object file in the temporary directory.
        // This ensures that we use a temp path for object files created for
        // C++ files added by users as well.
        auto obj = hilti::rt::filesystem::temp_directory_path() /
                   util::fmt("%s_%" PRIx64 ".o", path.filename().c_str(), _hash);

        args.emplace_back("-o");
        args.push_back(obj);
        _objects.push_back(std::move(obj));

        args.push_back(hilti::rt::filesystem::canonical(path));

        auto cxx = hilti::configuration().cxx;
        if ( const auto& launcher = hilti::configuration().cxx_launcher; launcher && ! launcher->empty() ) {
            args.insert(args.begin(), cxx);
            cxx = *launcher;
        }

        if ( auto rc = _runner._scheduleJob(cxx, std::move(args)); ! rc )
            errors.push_back(rc.error());
    }

    if ( auto rc = _runner._waitForJobs(); ! rc )
        errors.push_back(rc.error());

    if ( ! errors.empty() )
        return errors.front();

    return Nothing();
}

hilti::Result<std::shared_ptr<const Library>> JIT::_link() {
    util::timing::Collector _("hilti/jit/link");
    HILTI_DEBUG(logging::debug::Jit, "linking object files");

    if ( _objects.empty() )
        return result::Error("no object code to link");

    // Link all object files together into a shared library.
    std::vector<std::string> args;

    if ( options().debug )
        args = hilti::configuration().hlto_ld_flags_debug;
    else
        args = hilti::configuration().hlto_ld_flags_release;

    // Create a random temporary file owned only by us so we are not racing
    // with other processes attempting to create the same output file.
    //
    // We create this file in the same location as the final file so we can
    // perform an atomic move below.
    std::string lib0 = hilti::rt::filesystem::temp_directory_path() / "spicy-jit-hlto-XXXXXXXXXXXX";
    if ( auto fd = ::mkstemp(lib0.data()); fd == -1 )
        rt::fatalError(util::fmt("could not create temporary file: %s", strerror(errno)));
    else
        ::close(fd);

    args.emplace_back("-o");
    args.push_back(lib0);

    for ( const auto& path : _objects ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("  - %s", path.native()));

        // Double check that we really got the file.
        if ( ! hilti::rt::filesystem::exists(path) )
            return result::Error(
                util::fmt("missing object file %s, C++ compiler is probably not working", path.native()));

        args.push_back(path);

        if ( _dump_code ) {
            // Logging to driver because that's where all the other "saving to ..." messages go.
            auto dbg = util::fmt("dbg.%s", path.native());
            HILTI_DEBUG(logging::debug::Driver, util::fmt("saving object file to %s", dbg));

            std::error_code ec;
            hilti::rt::filesystem::copy(path, dbg, hilti::rt::filesystem::copy_options::overwrite_existing,
                                        ec); // will save into current directory; ignore errors
        }
    }

    // Add additional shared libraries or static archives to the link. This needs to happen
    // after we added the objects to make sure we pull in symbols used in the objects.
    for ( const auto& lib : options().cxx_link )
        if ( ! lib.empty() )
            args.emplace_back(lib);

    // We are using the compiler as a linker here, no need to use a compiler launcher.
    // Since we are writing to a random temporary file non of this would cache anyway.
    if ( auto rc = _runner._scheduleJob(hilti::configuration().cxx, std::move(args)); ! rc )
        return rc.error();

    if ( auto rc = _runner._waitForJobs(); ! rc )
        return rc.error();

    // Atomically move the temporary file to its final location. With that
    // even with concurrent saves to the same final path other processes should
    // always see a consistent version of the contents of that file.
    auto lib = hilti::rt::filesystem::temp_directory_path() / util::fmt("__library__%" PRIx64 ".hlto", _hash);
    std::error_code ec;
    hilti::rt::filesystem::rename(lib0, lib, ec);
    if ( ec )
        rt::fatalError(util::fmt("could not move file %s to final location %s: %s", lib0, lib, ec.message()));

    // Instantiate the library object from the file on disk, and set it up
    // to delete the file & its directory on destruction.
    bool keep_tmps = options().keep_tmps;
    auto library = std::shared_ptr<const Library>(new Library(lib), [keep_tmps](const Library* library) {
        if ( ! keep_tmps ) {
            auto remove = library->remove();
            if ( ! remove )
                logger().warning(util::fmt("could not remove JIT library: %s", remove.error()));
        }

        delete library;
    });

    if ( _dump_code ) {
        // Logging to driver because that's where all the other "saving to ..." messages go.
        const auto* dbg = "dbg.__library__.hlto";
        HILTI_DEBUG(logging::debug::Driver, util::fmt("saving library to %s", dbg));
        library->save(dbg); // will go into current directory
    }

    return library;
}

Result<JIT::JobRunner::JobID> JIT::JobRunner::_scheduleJob(const hilti::rt::filesystem::path& cmd,
                                                           std::vector<std::string> args) {
    CmdLine cmdline = {cmd.native()};

    for ( auto&& a : args )
        cmdline.push_back(std::move(a));

    auto jid = ++job_counter;
    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] %s", jid, util::join(cmdline, " ")));

    jobs_pending.emplace_back(jid, cmdline);
    return jid;
}

Result<Nothing> JIT::JobRunner::_spawnJob() {
    if ( jobs_pending.empty() )
        return {};

    auto [jid, cmdline] = jobs_pending.front();
    jobs_pending.pop_front();

    Job& job = jobs[jid];
    job.cmdline = util::join(cmdline, " ");
    job.process = std::make_unique<reproc::process>();

    if ( auto path = hilti::rt::createTemporaryFile("hilti-jit-output") ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] writing process output to %s", jid, *path));
        job.output = *path;
    }
    else {
        jobs.erase(jid);
        return path.error();
    }

    reproc::options options;
    options.redirect.path = job.output.c_str();

    auto ec = job.process->start(cmdline, options);

    if ( ec ) {
        jobs.erase(jid);
        return result::Error(util::fmt("process '%s' failed to start: %s", util::join(cmdline), ec.message()));
    }

    if ( auto [pid, ec] = job.process->pid(); ! ec ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] -> pid %u", jid, pid));
    }
    else {
        jobs.erase(jid);
        return result::Error(
            util::fmt("could not determine PID of process '%s %s': %s", util::join(cmdline), ec.message()));
    }

    return {};
}

Result<Nothing> JIT::JobRunner::_waitForJobs() {
    if ( jobs_pending.empty() && jobs.empty() )
        return Nothing();

    // Cap parallelism for background jobs.
    //
    // - if `HILTI_JIT_SEQUENTIAL` is used all parallelism is disabled and
    //   exactly one job is used.
    // - if `HILTI_JIT_PARALLELISM` is set it is interpreted as the maximum
    //   number of parallel jobs to use
    // - by default we use one job per available CPU (on some platforms
    //   `std::thread::hardware_concurrency` can return 0, so use one job
    //   there)
    auto hilti_jit_parallelism = hilti::rt::getenv("HILTI_JIT_PARALLELISM");

    uint64_t parallelism = 1;
    if ( hilti::rt::getenv("HILTI_JIT_SEQUENTIAL").hasValue() )
        parallelism = 1;
    else if ( auto e = hilti::rt::getenv("HILTI_JIT_PARALLELISM") )
        parallelism = util::charsToUInt64(e->c_str(), 10, [&]() {
            rt::fatalError(util::fmt("expected unsigned integer but received '%s' for HILTI_JIT_PARALLELISM", *e));
        });
    else {
        auto j = std::thread::hardware_concurrency();
        if ( j == 0 )
            rt::warning(
                "could not detect hardware level of concurrency, will use one thread for background compilation. "
                "Use "
                "`HILTI_JIT_PARALLELISM` to override");
        parallelism = std::max(j, 1U);
    }

    std::vector<result::Error> errors;
    hilti::rt::filesystem::remove(UserDiagnosticsFile);

    while ( ! jobs_pending.empty() || ! jobs.empty() ) {
        // If we still have jobs pending, spawn up to `parallelism` parallel background jobs.
        while ( ! jobs_pending.empty() && jobs.size() < parallelism )
            _spawnJob();

        std::vector<reproc::event::source> sources;
        std::vector<JobID> ids;

        for ( auto&& [id, job] : jobs ) {
            sources.push_back(
                reproc::event::source{.process = *job.process,
                                      .interests = reproc::event::out | reproc::event::err | reproc::event::exit,
                                      .events = 0});

            ids.push_back(id);
        }

        auto ec = reproc::poll(sources.data(), sources.size());

        if ( ec )
            return result::Error(util::fmt("could not wait for processes: %s", ec.message()));

        for ( size_t i = 0; i < sources.size(); ++i ) {
            auto&& source = sources[i];
            auto id = ids[i];
            auto& job = jobs[id];

            if ( ! source.events )
                continue;

            if ( source.events & reproc::event::exit ) {
                // Collect the exist status.
                auto [status, ec] = job.process->wait(reproc::milliseconds(0));

                if ( ec ) {
                    jobs.erase(id);
                    errors.emplace_back(util::fmt("could not wait for process: %s", ec.message()));
                }

                HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] exited with code %d", id, status));

                if ( status != 0 ) {
                    _recordUserDiagnostics(id, job);
                    jobs.erase(id);
                    errors.emplace_back("JIT compilation failed");
                }

                jobs.erase(id);
            }
        }
    }

    if ( ! errors.empty() )
        return errors.front();

    return Nothing();
}

void JIT::JobRunner::_recordUserDiagnostics(JobID jid, const Job& job) {
    auto add_header = ! rt::filesystem::exists(UserDiagnosticsFile);

    if ( add_header ) {
        // Record version of C++ compiler.
        reproc::options options;
        options.redirect.path = UserDiagnosticsFile.c_str();
        std::array<std::string, 2> cmdline = {hilti::configuration().cxx.c_str(), "--version"};
        reproc::run(cmdline, options);
    }

    std::ofstream out(UserDiagnosticsFile, std::ios::app);
    if ( ! out ) {
        logger().warning(
            util::fmt("could not open diagnostics file %s for writing: %s", UserDiagnosticsFile, ::strerror(errno)));
        return;
    }

    // Copy the output of the process over into the diagnostics file
    std::ifstream in(job.output);
    if ( ! in ) {
        logger().warning(
            util::fmt("could not open process output file %s for reading: %s", job.output, ::strerror(errno)));
        return;
    }

    if ( add_header )
        out << "HILTI version " << hilti::configuration().version_string_long << "\n\n";

    out << util::fmt("## [job %" PRIu64 "] %s\n\n", jid, job.cmdline);

    std::string line;
    while ( std::getline(in, line) )
        out << line << '\n';
}

JIT::JobRunner::JobRunner() {
    // reproc refuses to run on setups with a too high rlimit for the number of open files,
    // https://github.com/DaanDeMeyer/reproc/blob/main/reproc/src/process.posix.c#L103.
    // Since this leads to very intransparent errors try to set a lower limit
    // if we are on such a machine so things mostly just work.
    struct ::rlimit limit;
    if ( ::getrlimit(RLIMIT_NOFILE, &limit) != 0 )
        logger().internalError(
            util::fmt("cannot get limit for number of open files ('ulimit -n'): %s", ::strerror(errno)));

    constexpr auto reproc_max_fd_limit = 1024 * 1024;

    if ( limit.rlim_cur >= reproc_max_fd_limit ) {
        limit.rlim_cur = reproc_max_fd_limit;
        if ( ::setrlimit(RLIMIT_NOFILE, &limit) != 0 ) {
            logger().internalError(
                util::fmt("cannot set limit for number of open files ('ulimit -n %d'), please set it in your "
                          "environment: %s",
                          reproc_max_fd_limit, ::strerror(errno)));
        }
    }
}

void JIT::add(CxxCode d) {
    // Include all added codes in the JIT hash. This makes JIT invocations
    // unique and e.g., prevents us from generating the same output file if the
    // same module is seen in different compiler invocations.
    if ( const auto& code = d.code() )
        _hash = rt::hashCombine(_hash, std::hash<std::string>{}(*code));

    _codes.push_back(std::move(d));
}

void JIT::add(const hilti::rt::filesystem::path& p) {
    // Include all added files in the JIT hash. This makes JIT invocations
    // unique and e.g., prevents us from generating the same output file if the
    // same module is seen in different compiler invocations.
    _hash = rt::hashCombine(_hash, std::hash<std::string>{}(p));

    _files.push_back(p);
}
