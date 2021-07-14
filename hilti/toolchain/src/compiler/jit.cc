// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <array>
#include <fstream>
#include <utility>

#include <hilti/rt/init.h>
#include <hilti/rt/util.h>

#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/cxx/unit.h>
#include <hilti/compiler/jit.h>

#include <reproc++/drain.hpp>
#include <reproc++/reproc.hpp>

using namespace hilti;

void hilti::JIT::Job::collectOutputs(int events) {
    if ( ! process )
        return;

    if ( events & reproc::event::err ) {
        std::array<uint8_t, 4096> buffer;
        if ( auto [size, ec] = process->read(reproc::stream::err, buffer.begin(), buffer.size()); size && ! ec )
            stderr_.append(reinterpret_cast<const char*>(buffer.begin()), size);
    }

    if ( events & reproc::event::out ) {
        std::array<uint8_t, 4096> buffer;
        if ( auto [size, ec] = process->read(reproc::stream::out, buffer.begin(), buffer.size()); size && ! ec )
            stdout_.append(reinterpret_cast<const char*>(buffer.begin()), size);
    }
}

namespace hilti::logging::debug {
inline const DebugStream Driver("driver");
} // namespace hilti::logging::debug

// Wrapper around ::mkdtemp().
static hilti::Result<hilti::rt::filesystem::path> _make_tmp_directory() {
    std::string path = hilti::rt::filesystem::temp_directory_path() / "hilti.XXXXXXXXX";
    char buffer[path.size() + 1];
    memcpy(buffer, path.c_str(), path.size() + 1);
    if ( ::mkdtemp(buffer) )
        return hilti::rt::filesystem::path(buffer);
    else
        return result::Error("cannot create JIT temp directory");
}

CxxCode::CxxCode(const detail::cxx::Unit& u) {
    std::stringstream buffer;
    u.print(buffer);
    load(u.moduleID(), buffer);
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

JIT::JIT(std::shared_ptr<Context> context, bool dump_code) : _context(std::move(context)), _dump_code(dump_code) {}

JIT::~JIT() { _finish(); }

hilti::Result<std::shared_ptr<const Library>> JIT::build() {
    util::timing::Collector _("hilti/jit");

    if ( auto rc = _initialize(); ! rc )
        return rc.error();

    if ( auto rc = _checkCompiler(); ! rc )
        return rc.error();

    if ( auto rc = _compile(); ! rc )
        return rc.error();

    auto library = _link();
    _finish(); // clean up no matter if successful
    return library;
}

hilti::Result<Nothing> JIT::_initialize() {
    _tmpdir = hilti::rt::TemporaryDirectory();
    HILTI_DEBUG(logging::debug::Jit, util::fmt("temporary directory %s", _tmpdir->path().native()));
    return Nothing();
}

hilti::Result<Nothing> JIT::_checkCompiler() {
    auto cxx = hilti::configuration().cxx;

    // We ignore the output, just see if running the compiler works. `-dumpversion`
    // works with both GCC and clang, but unlikely to be supported by something
    // other than a compiler.
    if ( auto rc = _spawnJob(cxx, {"-dumpversion"}); ! rc )
        return result::Error(util::fmt("C++ compiler not available or not functioning (looking for %s)", cxx),
                             rc.error().context());

    if ( auto rc = _waitForJobs(); ! rc )
        return result::Error(util::fmt("C++ compiler not available or not functioning (looking for %s)", cxx),
                             rc.error().context());

    return Nothing();
}

void JIT::_finish() {
    _objects.clear();

    for ( auto&& [id, job] : _jobs ) {
        auto [status, ec] = job.process->stop(reproc::stop_actions{
            .first = {.action = reproc::stop::terminate, .timeout = reproc::milliseconds(1000)},
            .second = {.action = reproc::stop::kill, .timeout = reproc::milliseconds::max()},
        });

        if ( ec )
            HILTI_DEBUG(logging::debug::Jit, util::fmt("failed to stop job: %s", ec.message()));

        // Since we terminated the process forcibly, which if the process was still running probably
        // triggered a non-zero exist status, we ignore the status returned from `stop`.
    }

    _jobs.clear();
    _tmp_counters.clear();
    _tmpdir.reset();
}

hilti::Result<Nothing> JIT::_compile() {
    util::timing::Collector _("hilti/jit/compile");

    if ( _codes.empty() && _files.empty() )
        return Nothing();

    auto cc_files = _files;

    // Write all in-memory code into temporary files.
    for ( const auto& code : _codes ) {
        auto id = hilti::rt::filesystem::path(code.id());
        if ( id.empty() )
            id = "code"; // dummy name

        auto cc = _makeTmp(id.stem(), "cc");
        HILTI_DEBUG(logging::debug::Jit, util::fmt("writing temporary code for %s to %s", id, cc.filename().native()));
        code.save(cc);

        if ( _dump_code ) {
            // Logging to driver because that's where all the other "saving to ..." messages go.
            auto dbg = util::fmt("dbg.%s", cc.filename().native());
            HILTI_DEBUG(logging::debug::Driver, util::fmt("saving code for %s to %s", id, dbg));

            std::error_code ec;
            hilti::rt::filesystem::copy(cc, dbg, hilti::rt::filesystem::copy_options::overwrite_existing,
                                        ec); // will save into current directory; ignore errors
        }

        cc_files.push_back(cc);
    }

    bool sequential = hilti::rt::getenv("HILTI_JIT_SEQUENTIAL").has_value();

    // Compile all C++ files.
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
            args.push_back("-I");
            args.push_back(i);
        }

        if ( auto path = getenv("HILTI_CXX_INCLUDE_DIRS") ) {
            for ( auto&& dir : hilti::rt::split(path, ":") ) {
                if ( dir.size() ) {
                    args.push_back("-I");
                    args.push_back(std::string(dir));
                }
            }
        }

        auto obj = path.stem().native() + std::string(".o");
        args.push_back("-o");
        args.push_back(obj); // will be relative to tmpdir
        _objects.push_back(obj);

        args.push_back(hilti::rt::filesystem::canonical(path));

        if ( auto rc = _spawnJob(hilti::configuration().cxx, std::move(args)); ! rc )
            return rc.error();

        if ( sequential ) {
            if ( auto rc = _waitForJobs(); ! rc )
                return rc.error();
        }
    }

    // Noop if sequential.
    if ( auto rc = _waitForJobs(); ! rc )
        return rc.error();

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

    auto lib = _makeTmp("__library__", "hlto");
    args.push_back("-o");
    args.push_back(lib.filename());

    for ( const auto& path : _objects ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("  - %s", path.native()));

        // Double check that we really got the file.
        if ( ! hilti::rt::filesystem::exists(_tmpdir->path() / path) )
            return result::Error(
                util::fmt("missing object file %s, C++ compiler is probably not working", path.native()));

        args.push_back(path);

        if ( _dump_code ) {
            // Logging to driver because that's where all the other "saving to ..." messages go.
            auto dbg = util::fmt("dbg.%s", path.native());
            HILTI_DEBUG(logging::debug::Driver, util::fmt("saving object file to %s", dbg));

            std::error_code ec;
            hilti::rt::filesystem::copy(_tmpdir->path() / path, dbg,
                                        hilti::rt::filesystem::copy_options::overwrite_existing,
                                        ec); // will save into current directory; ignore errors
        }
    }

    if ( auto rc = _spawnJob(hilti::configuration().cxx, std::move(args)); ! rc )
        return rc.error();

    if ( auto rc = _waitForJobs(); ! rc )
        return rc.error();

    // Copy the library to a new location that won't be deleted when JIT has
    // finished. The library itself will clean up the file when no longer
    // needed.
    auto tmp_dir = _make_tmp_directory();
    if ( ! tmp_dir )
        return tmp_dir.error();

    auto ext_lib = *tmp_dir / lib.filename();

    try {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("copying library to %s", ext_lib));
        hilti::rt::filesystem::create_directory(ext_lib.parent_path());
        hilti::rt::filesystem::rename(_tmpdir->path() / lib, ext_lib);
    } catch ( hilti::rt::filesystem::filesystem_error& e ) {
        return result::Error(e.what());
    }

    // Instantiate the library object from the file on disk, and set it up
    // to delete the file & its directory on destruction.
    auto library = std::shared_ptr<const Library>(new Library(ext_lib), [ext_lib](const Library* library) {
        auto remove = library->remove();
        if ( ! remove )
            logger().warning(util::fmt("could not remove JIT library: %s", remove.error()));

        std::error_code ec;
        if ( ! hilti::rt::filesystem::remove(ext_lib.parent_path(), ec) )
            logger().warning(util::fmt("could not remove JIT temporary library directory: %s", ec.message()));

        delete library;
    });

    if ( _dump_code ) {
        // Logging to driver because that's where all the other "saving to ..." messages go.
        auto dbg = "dbg.__library__.hlto";
        HILTI_DEBUG(logging::debug::Driver, util::fmt("saving library to %s", dbg));
        library->save(dbg); // will go into current directory
    }

    return library;
}

Result<JIT::JobID> JIT::_spawnJob(hilti::rt::filesystem::path cmd, std::vector<std::string> args) {
    std::vector<std::string> cmdline = {cmd.native()};

    for ( auto&& a : args )
        cmdline.push_back(std::move(a));

    auto jid = ++_job_counter;
    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] %s", jid, util::join(cmdline, " ")));

    Job& job = _jobs[jid];
    job.process = std::make_unique<reproc::process>();

    reproc::options options;
    options.working_directory = _tmpdir->path().c_str();
    options.redirect.in.type = reproc::redirect::discard;
    options.redirect.out.type = reproc::redirect::default_;
    options.redirect.err.type = reproc::redirect::default_;

    auto ec = job.process->start(cmdline, options);

    if ( ec ) {
        _jobs.erase(jid);
        return result::Error(
            util::fmt("process '%s %s' failed to start: %s", cmd.native(), util::join(args), ec.message()));
    }

    if ( auto [pid, ec] = job.process->pid(); ! ec ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] -> pid %u", jid, pid));
    }
    else {
        _jobs.erase(jid);
        return result::Error(
            util::fmt("could not determine PID of process '%s %s': %s", cmd.native(), util::join(args), ec.message()));
    }

    return jid;
}

Result<Nothing> JIT::_waitForJobs() {
    if ( _jobs.empty() )
        return Nothing();

    while ( ! _jobs.empty() ) {
        std::vector<reproc::event::source> sources;
        std::vector<JobID> ids;

        for ( auto&& [id, job] : _jobs ) {
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
            auto& job = _jobs[id];

            if ( ! source.events )
                continue;

            job.collectOutputs(source.events);

            if ( source.events & reproc::event::exit ) {
                // Collect the exist status.
                auto [status, ec] = job.process->wait(reproc::milliseconds(0));

                if ( ec ) {
                    _jobs.erase(id);
                    return result::Error(util::fmt("could not wait for process: %s", ec.message()));
                }

                HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] exited with code %d", id, status));

                if ( ! job.stdout_.empty() )
                    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] stdout: %s", id, util::trim(job.stdout_)));

                if ( ! job.stderr_.empty() )
                    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] stderr: %s", id, util::trim(job.stderr_)));

                if ( status != 0 ) {
                    std::string stderr__ = job.stderr_.empty() ?
                                               "(no error output)" :
                                               std::string("JIT output: \n") + util::trim(job.stderr_);
                    _jobs.erase(id);
                    return result::Error("JIT compilation failed", stderr__);
                }

                _jobs.erase(id);
            }
        }
    }

    return Nothing();
}

hilti::rt::filesystem::path JIT::_makeTmp(std::string base, std::string ext) {
    // Will be used relative to tmpdir.
    auto& counter = _tmp_counters[base];

    if ( ++counter > 1 )
        return _tmpdir->path() / util::fmt("%s.%u.%s", base, counter, ext);
    else
        return _tmpdir->path() / util::fmt("%s.%s", base, ext);
}
