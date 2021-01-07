// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <utility>

#include <hilti/rt/init.h>

#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/cxx/unit.h>
#include <hilti/compiler/jit.h>

using namespace hilti;

namespace hilti::logging::debug {
inline const DebugStream Driver("driver");
} // namespace hilti::logging::debug

// Wrapper around ::mkdtemp().
static hilti::Result<hilti::rt::filesystem::path> _make_tmp_directory() {
    std::string path = hilti::rt::filesystem::temp_directory_path() / "hilti.XXXXXXXXX";
    char buffer[path.size() + 1];
    strcpy(buffer, path.c_str());
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

    if ( auto rc = _checkCompiler(); ! rc )
        return rc.error();

    if ( auto rc = _initialize(); ! rc )
        return rc.error();

    if ( auto rc = _compile(); ! rc )
        return rc.error();

    auto library = _link();
    _finish(); // clean up no matter if successful
    return library;
}

hilti::Result<Nothing> JIT::_checkCompiler() {
    auto cxx = hilti::configuration().cxx;

    // We ignore the output, just see if running the compiler works. `-dumpversion`
    // works with both GCC and clang, but unlikely to be supported by something
    // other than a compiler.
    if ( auto rc = _spawnJob(cxx, {"-dumpversion"}); ! rc )
        return result::Error(util::fmt("C++ compiler not available or not functioning (looking for %s)", cxx), rc.error().context());

    if ( auto rc = _waitForJobs(); ! rc )
        return result::Error(util::fmt("C++ compiler not available or not functioning (looking for %s)", cxx), rc.error().context());

    return Nothing();
}

hilti::Result<Nothing> JIT::_initialize() {
    // Create tmp directory for compilation.
    auto tmpdir = _make_tmp_directory();
    if ( ! tmpdir )
        return tmpdir.error();

    _tmpdir = *tmpdir;
    HILTI_DEBUG(logging::debug::Jit, util::fmt("temporary directory %s", _tmpdir.native()));
    return Nothing();
}

void JIT::_finish() {
    // Kill remaining jobs.
    for ( auto& [id, job] : _jobs ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] terminating process", id));
        job.process->kill(true);
    }

    // Remove any temporaries.
    if ( ! _tmpdir.empty() )
        hilti::rt::filesystem::remove_all(_tmpdir);

    _objects.clear();
    _jobs.clear();
    _tmp_counters.clear();
    _tmpdir.clear();
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
            hilti::rt::filesystem::copy(cc, dbg,
                                        hilti::rt::filesystem::copy_options::overwrite_existing); // will go into
                                                                                                  // current directory
        }

        cc_files.push_back(cc);
    }

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

        auto obj = path.stem().native() + std::string(".o");
        args.push_back("-o");
        args.push_back(obj); // will be relative to tmpdir
        _objects.push_back(obj);

        args.push_back(hilti::rt::filesystem::absolute(path));

        if ( auto rc = _spawnJob(hilti::configuration().cxx, std::move(args)); ! rc )
            return rc.error();
    }

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
        if ( ! hilti::rt::filesystem::exists(_tmpdir / path) )
            return result::Error(util::fmt("missing object file %s, C++ compiler is probably not working", path.native()));

        args.push_back(path);

        if ( _dump_code ) {
            // Logging to driver because that's where all the other "saving to ..." messages go.
            auto dbg = util::fmt("dbg.%s", path.native());
            HILTI_DEBUG(logging::debug::Driver, util::fmt("saving object file to %s", dbg));
            hilti::rt::filesystem::copy(_tmpdir / path, dbg,
                                        hilti::rt::filesystem::copy_options::overwrite_existing); // will go into
                                                                                                  // current directory
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
        hilti::rt::filesystem::rename(_tmpdir / lib, ext_lib);
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
    job.process = std::make_unique<TinyProcessLib::Process>(
        cmdline, _tmpdir, [&job](const char* bytes, size_t n) { job.stdout_ += std::string(bytes, n); },
        [&job](const char* bytes, size_t n) { job.stderr_ += std::string(bytes, n); });

    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] -> pid %u", jid, job.process->get_id()));

    // TinyProcessLibProcess fails silently if there's a problem, but leaves the PID unset.
    if ( job.process->get_id() <= 0 )
        return result::Error(util::fmt("process failed to start: %s %s", cmd.native(), util::join(args)));

    return jid;
}

Result<Nothing> JIT::_waitForJob(JobID id) {
    if ( _jobs.find(id) == _jobs.end() )
        return result::Error(util::fmt("unknown JIT job %u", id));

    // Now move it out of the map.
    const auto& job = _jobs[id];
    auto ec = job.process->get_exit_status();

    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] exited with code %d", id, ec));

    if ( job.stdout_.size() )
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] stdout: %s", id, job.stdout_));

    if ( job.stderr_.size() )
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] stderr: %s", id, job.stderr_));

    if ( ec != 0 ) {
        std::string stderr_ =
            job.stderr_.size() ? std::string("JIT output: \n") + util::trim(job.stderr_) : "(no error output)";
        _jobs.erase(id);
        return result::Error("JIT compilation failed", stderr_);
    }

    _jobs.erase(id);
    return Nothing();
}

Result<Nothing> JIT::_waitForJobs() {
    while ( _jobs.size() ) {
        if ( auto rc = _waitForJob(_jobs.begin()->first); ! rc )
            // We stop after the first one failing.
            return rc;
    }

    return Nothing();
}

hilti::rt::filesystem::path JIT::_makeTmp(std::string base, std::string ext) {
    // Will be used relative to tmpdir.
    auto& counter = _tmp_counters[base];

    if ( ++counter > 1 )
        return _tmpdir / util::fmt("%s.%u.%s", base, counter, ext);
    else
        return _tmpdir / util::fmt("%s.%s", base, ext);
}
