// Copyrights (c) 2020 by the Zeek Project. See LICENSE for details.

#include <stdexcept>

#include <hilti/rt/filesystem.h>

#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/jit/cxx.h>
#include <hilti/compiler/jit.h>

#include "filesystem/include/ghc/filesystem.hpp"
#include <tiny-process-library/process.hpp>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::jit;

Cxx::Cxx(std::shared_ptr<Context> context) : _context(context) {
    // Create directory for tmp files.
    std::string path = hilti::rt::filesystem::temp_directory_path() / "hilti.XXXXXXXXX";
    char buffer[path.size() + 1];
    strcpy(buffer, path.c_str());
    if ( ! ::mkdtemp(buffer) )
        throw std::runtime_error("cannot create JIT temp directory");

    _workdir = buffer;
    HILTI_DEBUG(logging::debug::Jit, util::fmt("working directory %s", _workdir.native()));
}

Cxx::~Cxx() {
    _terminateAll();

    if ( ! _workdir.empty() )
        hilti::rt::filesystem::remove_all(_workdir);
}

bool Cxx::compile(const CxxCode& code) {
    auto id = hilti::rt::filesystem::path(code.id());
    if ( id.empty() )
        id = "code"; // dummy name

    auto out = _makeTmp(id.stem(), "cc");
    HILTI_DEBUG(logging::debug::Jit, util::fmt("saving code for %s to %s", id, out.filename().native()));
    code.save(out);
    return compile(out);
}

bool Cxx::compile(const hilti::rt::filesystem::path& path) {
    util::timing::Collector _("hilti/jit/compile/cxx");

    // Build standard compiler arguments.
    std::vector<std::string> args;

    if ( options().debug )
        args = hilti::configuration().jit_cxx_flags_debug;
    else
        args = hilti::configuration().jit_cxx_flags_release;

    // For debug output on compilation:
    // args.push_back("-v");
    // args.push_back("-###");

    for ( const auto& i : options().cxx_include_paths ) {
        args.push_back("-I");
        args.push_back(i);
    }

    auto output = path.stem().native() + std::string(".o");
    args.push_back("-o");
    args.push_back(output); // will be relative to workdir

    args.push_back(hilti::rt::filesystem::absolute(path));

    if ( auto rc = _spawnJob(hilti::configuration().cxx, std::move(args)); ! rc ) {
        std::cerr << rc.error() << std::endl; // TODO: change API to pass this back
        return false;
    }

    if ( auto rc = _waitForJobs(); ! rc ) {
        std::cerr << rc.error() << std::endl; // TODO: change API to pass this back
        return false;
    }

    _objects.push_back(std::move(output));
    return true;
}

Result<Nothing> Cxx::jit() {
    util::timing::Collector _("hilti/jit/compile/jit");

    if ( _objects.empty() )
        return Nothing();

    // Double check that we really got all the object files.
    for ( const auto& p : _objects ) {
        if ( ! hilti::rt::filesystem::exists(_workdir / p) )
            return result::Error(util::fmt("missing object file %s", p.native()));
    }

    // Link all object files together into a shared library.
    std::vector<std::string> args;

    if ( options().debug )
        args = hilti::configuration().jit_ld_flags_debug;
    else
        args = hilti::configuration().jit_ld_flags_release;

    auto output = _makeTmp("__library__", "hlto");
    args.push_back("-o");
    args.push_back(output.filename());

    for ( const auto& p : _objects )
        args.push_back(p);

    if ( auto rc = _spawnJob(hilti::configuration().cxx, std::move(args)); ! rc )
        return rc.error();

    if ( auto rc = _waitForJobs(); ! rc )
        return rc.error();

    _library = std::shared_ptr<const Library>(new Library(output), [](const Library* library) {
        auto remove = library->remove();
        if ( ! remove )
            logger().warning(util::fmt("could not remove JIT library: %s", remove.error()));

        delete library;
    });

    return Nothing();
}

std::shared_ptr<const Library> Cxx::retrieveLibrary() const { return _library; }

void Cxx::setDumpCode() { // TODO
}

std::string Cxx::compilerVersion() { return "HOST_COMPILER_TODO"; }

Result<Cxx::JobID> Cxx::_spawnJob(hilti::rt::filesystem::path cmd, std::vector<std::string> args) {
    std::vector<std::string> cmdline = {cmd.native()};

    for ( auto&& a : args )
        cmdline.push_back(std::move(a));

    auto jid = ++_job_counter;

    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] %s", jid, util::join(cmdline, " ")));

    Job& job = _jobs[jid];
    job.process = std::make_unique<TinyProcessLib::Process>(
        cmdline, _workdir, [&job](const char* bytes, size_t n) { job.stdout += std::string(bytes, n); },
        [&job](const char* bytes, size_t n) { job.stderr += std::string(bytes, n); });

    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] -> pid %u", jid, job.process->get_id()));

    // TinyProcessLibProcess fails silently if there's a problem, but leaves
    // the PID unset.

    if ( job.process->get_id() <= 0 )
        return result::Error(util::fmt("process failed to start: %s %s", cmd.native(), util::join(args)));

    return jid;
}

Result<Nothing> Cxx::_waitForJob(JobID id) {
    if ( _jobs.find(id) == _jobs.end() )
        return result::Error(util::fmt("unknown JIT job %u", id));

    // Now move it out of the map.
    const auto& job = _jobs[id];
    auto ec = job.process->get_exit_status();

    HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] exited with code %d", id, ec));

    if ( job.stdout.size() )
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] stdout: %s", id, job.stdout));

    if ( job.stderr.size() )
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] stderr: %s", id, job.stderr));

    if ( ec != 0 ) {
        std::string stderr = job.stderr.size() ? util::trim(job.stderr) : " [no error output]";
        _jobs.erase(id);
        return result::Error(stderr);
    }

    _jobs.erase(id);
    return Nothing();
}

Result<Nothing> Cxx::_waitForJobs() {
    while ( _jobs.size() ) {
        if ( auto rc = _waitForJob(_jobs.begin()->first); ! rc ) {
            // We abort after the first one failing.
            _terminateAll();
            return rc;
        }
    }

    return Nothing();
}

void Cxx::_terminateAll() {
    for ( auto& [id, job] : _jobs ) {
        HILTI_DEBUG(logging::debug::Jit, util::fmt("[job %u] terminating process", id));
        job.process->kill(true);
    }

    _jobs.clear();
}

hilti::rt::filesystem::path Cxx::_makeTmp(std::string base, std::string ext) {
    // Will be used relative to workdir.
    auto& counter = _tmp_counters[base];

    if ( ++counter > 1 )
        return _workdir / util::fmt("%s.%u.%s", base, counter, ext);
    else
        return _workdir / util::fmt("%s.%s", base, ext);
}
