// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>

#include <spicy/rt/parser.h>

#include <hilti/ast/types/enum.h>
#include <hilti/base/util.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/plugin-jit.h>
#include <zeek-spicy/zeek-reporter.h>

// clang-format off
#include <compiler/debug.h>
#include <compiler/driver.h>
// clang-format on

// Zeek includes
#if ZEEK_DEBUG_BUILD
#define DEBUG
#endif
#include <Val.h>
#include <Var.h>
#undef DEBUG

namespace spicy::zeek::debug {
const hilti::logging::DebugStream ZeekPlugin("zeek");
}

#ifdef ZEEK_HAVE_JIT
plugin::Zeek_Spicy::PluginJIT SpicyPlugin;
plugin::Zeek_Spicy::Plugin* ::plugin::Zeek_Spicy::OurPlugin = &SpicyPlugin;
#endif

using namespace spicy::zeek;

void ::spicy::zeek::debug::do_log(const std::string_view& msg) {
    HILTI_RT_DEBUG("zeek", msg);
    HILTI_DEBUG(::spicy::zeek::debug::ZeekPlugin, std::string(msg));
}

void plugin::Zeek_Spicy::Driver::hookAddInput(const std::filesystem::path& path) {
    // Need to initialized before 1st input gets added, as the options need
    // to be in place.
    _initialize();
}

void plugin::Zeek_Spicy::Driver::hookAddInput(const hilti::Module& m, const std::filesystem::path& path) {
    // Need to initialized before 1st input gets added, as the options need
    // to be in place.
    _initialize();
}

void plugin::Zeek_Spicy::Driver::_initialize() {
    if ( _initialized )
        return;

    ZEEK_DEBUG("Initializing driver");

    // Initialize HILTI compiler options. We dont't use the `BifConst::*`
    // constants here as they may not have been initialized yet.
    hilti::Options hilti_options;

    hilti_options.debug = ::zeek::id::find_const("Spicy::debug")->AsBool();
    hilti_options.skip_validation = ::zeek::id::find_const("Spicy::skip_validation")->AsBool();
    hilti_options.optimize = ::zeek::id::find_const("Spicy::optimize")->AsBool();

    for ( auto i : hilti::util::split(spicy::zeek::configuration::CxxZeekIncludeDirectories, ":") )
        hilti_options.cxx_include_paths.emplace_back(i);

    hilti_options.cxx_include_paths.emplace_back(spicy::zeek::configuration::CxxBrokerIncludeDirectory);

    if ( hilti::configuration().uses_build_directory ) {
        hilti_options.cxx_include_paths.emplace_back(spicy::zeek::configuration::CxxAutogenIncludeDirectoryBuild);
        hilti_options.cxx_include_paths.emplace_back(spicy::zeek::configuration::CxxRuntimeIncludeDirectoryBuild);
    }
    else
        hilti_options.cxx_include_paths.emplace_back(
            spicy::zeek::configuration::CxxRuntimeIncludeDirectoryInstallation);

    for ( const auto& dir : _import_paths )
        hilti_options.library_paths.push_back(dir);

#ifdef DEBUG
    ZEEK_DEBUG("Search paths:");

    for ( const auto& x : hilti_options.library_paths ) {
        ZEEK_DEBUG(hilti::rt::fmt("  %s", x.native()));
    }
#endif

    // Initialize HILTI driver options.
    hilti::driver::Options driver_options;
    driver_options.logger = nullptr; // keep using the global logger, which we may have already configured
    driver_options.execute_code = true;
    driver_options.include_linker = true;
    driver_options.dump_code = ::zeek::id::find_const("Spicy::dump_code")->AsBool();
    driver_options.report_times = ::zeek::id::find_const("Spicy::report_times")->AsBool();

    for ( auto s :
          hilti::util::split(::zeek::id::find_const("Spicy::codegen_debug")->AsStringVal()->ToStdString(), ",") ) {
        s = hilti::util::trim(s);

        if ( s.size() && ! driver_options.logger->debugEnable(s) )
            reporter::fatalError(hilti::rt::fmt("Unknown Spicy debug stream '%s'", s));
    }

    if ( auto r =
             hilti_options.parseDebugAddl(::zeek::id::find_const("Spicy::debug_addl")->AsStringVal()->ToStdString());
         ! r )
        reporter::fatalError(r.error());

    // As it can be tricky on the Zeek side to set options from the command
    // line, we also support passing them in through environment variables.
    // This takes the same options as spicyc on the command line.
    if ( auto opts = getenv("SPICY_PLUGIN_OPTIONS") ) {
        if ( auto rc = parseOptionsPostScript(opts, &driver_options, &hilti_options); ! rc )
            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error parsing SPICY_PLUGIN_OPTIONS, %s", rc.error()));
    }

    setCompilerOptions(std::move(hilti_options));
    setDriverOptions(std::move(driver_options));

    hilti::Driver::initialize();
    _initialized = true;
}

void plugin::Zeek_Spicy::Driver::hookNewEnumType(const EnumInfo& e) {
    // Because we are running live within a Zeek, register the new enum type
    // immediately so that it'll be available when subsequent scripts are
    // parsed. (When running offline, the driver adds registration to the
    // Spicy code's initialization code.)
    auto labels = hilti::rt::transform(e.type.as<hilti::type::Enum>().labels(), [](const auto& l) {
        return std::make_tuple(l.id().str(), hilti::rt::integer::safe<int64_t>(l.value()));
    });

    hilti::rt::Vector<decltype(labels)::value_type> xs;
    xs.reserve(labels.size());
    std::copy(std::move_iterator(labels.begin()), std::move_iterator(labels.end()), std::back_inserter(xs));

    ::SpicyPlugin.registerEnumType(e.id.namespace_(), e.id.local(), std::move(xs));
}

plugin::Zeek_Spicy::PluginJIT::PluginJIT() {
    Dl_info info;
    if ( ! dladdr(&SpicyPlugin, &info) )
        reporter::fatalError("Spicy plugin cannot determine its file system path");

    _driver = std::make_unique<Driver>(info.dli_fname);
}

plugin::Zeek_Spicy::PluginJIT::~PluginJIT() {}

void plugin::Zeek_Spicy::PluginJIT::addLibraryPaths(const std::string& dirs) {
    plugin::Zeek_Spicy::Plugin::addLibraryPaths(dirs);

    for ( const auto& dir : hilti::rt::split(dirs, ":") )
        _driver->_import_paths.emplace_back(dir);
}

void plugin::Zeek_Spicy::PluginJIT::InitPreScript() {
    ZEEK_DEBUG("Beginning pre-script initialization (compiler)");

    if ( auto opts = getenv("SPICY_PLUGIN_OPTIONS") ) {
        if ( auto rc = Driver::parseOptionsPreScript(opts); ! rc )
            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error parsing SPICY_PLUGIN_OPTIONS, %s", rc.error()));
    }

    ZEEK_DEBUG("Done with pre-script initialization (compiler)");
    plugin::Zeek_Spicy::Plugin::InitPreScript();
}

void plugin::Zeek_Spicy::PluginJIT::InitPostScript() {
    ZEEK_DEBUG("Beginning post-script initialization (compiler)");

    for ( auto p : _driver->driverOptions().inputs ) {
        ZEEK_DEBUG(hilti::rt::fmt("Loading input file %s", p));
        if ( auto rc = _driver->loadFile(p); ! rc )
            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error loading %s: %s", p, rc.error().description()));
    }

    {
        // Compile all the inputs.
        ZEEK_DEBUG("Compiling input files");
        hilti::logging::DebugPushIndent _(debug::ZeekPlugin);

        if ( auto rc = _driver->compile(); ! rc )
            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error during compilation: %s", rc.error().description()));

        if ( ! _driver->driverOptions().output_path.empty() )
            // If an output path is set, we're in precompilation mode, just exit.
            exit(0);

        // If there are errors, compile() should have flagged that through its
        // exit code.
        assert(hilti::logger().errors() == 0);
    }

    ZEEK_DEBUG("Done with post-script initialization (compiler)");
    plugin::Zeek_Spicy::Plugin::InitPostScript();
}

int plugin::Zeek_Spicy::PluginJIT::HookLoadFile(const LoadType type, const std::string& file,
                                                const std::string& resolved) {
    auto ext = std::filesystem::path(file).extension();

    if ( ext == ".spicy" || ext == ".evt" || ext == ".hlt" || ext == ".hlto" ) {
        ZEEK_DEBUG(hilti::rt::fmt("Loading input file '%s'", file));
        if ( auto rc = _driver->loadFile(file); ! rc ) {
            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error loading %s: %s", file, rc.error().description()));
            return 0;
        }

        return 1;
    }

    return plugin::Zeek_Spicy::Plugin::HookLoadFile(type, file, resolved);
}
