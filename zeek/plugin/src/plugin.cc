// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>
#include <glob.h>

#include <exception>

#include <hilti/rt/autogen/version.h>
#include <hilti/rt/configuration.h>
#include <hilti/rt/filesystem.h>
#include <hilti/rt/init.h>
#include <hilti/rt/library.h>
#include <hilti/rt/types/vector.h>

#include <spicy/rt/init.h>
#include <spicy/rt/parser.h>

#include <hilti/ast/types/enum.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/file-analyzer.h>
#ifdef HAVE_PACKET_ANALYZERS
#include <zeek-spicy/packet-analyzer.h>
#endif
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/protocol-analyzer.h>
#include <zeek-spicy/zeek-compat.h>
#include <zeek-spicy/zeek-reporter.h>

namespace spicy::zeek::debug {
const hilti::logging::DebugStream ZeekPlugin("zeek");
}

plugin::Zeek_Spicy::Plugin SpicyPlugin;
plugin::Zeek_Spicy::Plugin* ::plugin::Zeek_Spicy::OurPlugin = &SpicyPlugin;

using namespace spicy::zeek;

plugin::Zeek_Spicy::Plugin::Plugin() {
#ifdef ZEEK_VERSION_NUMBER // Not available in Zeek 3.0 yet.
    if ( spicy::zeek::configuration::ZeekVersionNumber != ZEEK_VERSION_NUMBER )
        reporter::fatalError(
            hilti::util::fmt("Zeek version mismatch: running with Zeek %d, but plugin compiled for Zeek %s",
                             ZEEK_VERSION_NUMBER, spicy::zeek::configuration::ZeekVersionNumber));
#endif

    Dl_info info;
    if ( ! dladdr(&SpicyPlugin, &info) )
        reporter::fatalError("Spicy plugin cannot determine its file system path");

    _driver = std::make_unique<Driver>(info.dli_fname, spicy::zeek::configuration::ZeekVersionNumber);
}

void ::spicy::zeek::debug::do_log(const std::string& msg) {
    PLUGIN_DBG_LOG(*plugin::Zeek_Spicy::OurPlugin, "%s", msg.c_str());
    HILTI_RT_DEBUG("zeek", msg);
    HILTI_DEBUG(::spicy::zeek::debug::ZeekPlugin, msg);
}

void plugin::Zeek_Spicy::Driver::hookAddInput(const hilti::rt::filesystem::path& path) {
    // Need to initialized before 1st input gets added, as the options need
    // to be in place.
    _initialize();
}

void plugin::Zeek_Spicy::Driver::hookAddInput(const hilti::Module& m, const hilti::rt::filesystem::path& path) {
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


plugin::Zeek_Spicy::Plugin::~Plugin() {}

void plugin::Zeek_Spicy::Plugin::addLibraryPaths(const std::string& dirs) {
    for ( const auto& dir : hilti::rt::split(dirs, ":") )
        ::zeek::util::detail::add_to_zeek_path(std::string(dir)); // Add to Zeek's search path.

    for ( const auto& dir : hilti::rt::split(dirs, ":") )
        _driver->_import_paths.emplace_back(dir);
}

void plugin::Zeek_Spicy::Plugin::registerProtocolAnalyzer(const std::string& name, hilti::rt::Protocol proto,
                                                          const hilti::rt::Vector<hilti::rt::Port>& ports,
                                                          const std::string& parser_orig,
                                                          const std::string& parser_resp, const std::string& replaces) {
    ZEEK_DEBUG(hilti::rt::fmt("Have Spicy protocol analyzer %s", name));

    ProtocolAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_parser_orig = parser_orig;
    info.name_parser_resp = parser_resp;
    info.name_replaces = replaces;
    info.protocol = proto;
    info.ports = ports;
    info.subtype = _protocol_analyzers_by_subtype.size();
    _protocol_analyzers_by_subtype.push_back(std::move(info));

    if ( replaces.size() ) {
        if ( zeek::analyzer::Tag tag = ::zeek::analyzer_mgr->GetAnalyzerTag(replaces.c_str()) ) {
            ZEEK_DEBUG(hilti::rt::fmt("Disabling %s for %s", replaces, name));
            ::zeek::analyzer_mgr->DisableAnalyzer(tag);
        }
        else
            ZEEK_DEBUG(hilti::rt::fmt("%s i supposed to replace %s, but that does not exist", name, replaces, name));
    }
}

void plugin::Zeek_Spicy::Plugin::registerFileAnalyzer(const std::string& name,
                                                      const hilti::rt::Vector<std::string>& mime_types,
                                                      const std::string& parser) {
    ZEEK_DEBUG(hilti::rt::fmt("Have Spicy file analyzer %s", name));

    FileAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_parser = parser;
    info.mime_types = mime_types;
    info.subtype = _file_analyzers_by_subtype.size();
    _file_analyzers_by_subtype.push_back(std::move(info));
}

#ifdef HAVE_PACKET_ANALYZERS
void plugin::Zeek_Spicy::Plugin::registerPacketAnalyzer(const std::string& name, const std::string& parser) {
    ZEEK_DEBUG(hilti::rt::fmt("Have Spicy packet analyzer %s", name));

    PacketAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_parser = parser;
    info.subtype = _packet_analyzers_by_subtype.size();
    _packet_analyzers_by_subtype.push_back(std::move(info));
}
#endif

void plugin::Zeek_Spicy::Plugin::registerEnumType(
    const std::string& ns, const std::string& id,
    const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels) {
    if ( ::zeek::detail::lookup_ID(id.c_str(), ns.c_str()) )
        // Already exists, which means it's either done by the Spicy plugin
        // already, or provided manually. We leave it alone then.
        return;

    auto fqid = hilti::rt::fmt("%s::%s", ns, id);
    ZEEK_DEBUG(hilti::rt::fmt("Adding Zeek enum type %s", fqid));

    auto etype = ::spicy::zeek::compat::EnumType_New(fqid);

    for ( const auto& [lid, lval] : labels ) {
        auto name = ::hilti::rt::fmt("%s_%s", id, lid);
        etype->AddName(ns, name.c_str(), lval, true);
    }

    // Hack to prevent Zeekygen fromp reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script("<Spicy>");
    ::zeek::detail::set_location(::zeek::detail::Location("<Spicy>", 0, 0, 0, 0));

    auto zeek_id = ::zeek::detail::install_ID(id.c_str(), ns.c_str(), true, true);
    zeek_id->SetType(etype);
    zeek_id->MakeType();
}

const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForProtocolAnalyzer(const ::zeek::analyzer::Tag& tag,
                                                                               bool is_orig) {
    if ( is_orig )
        return _protocol_analyzers_by_subtype[tag.Subtype()].parser_orig;
    else
        return _protocol_analyzers_by_subtype[tag.Subtype()].parser_resp;
}

const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForFileAnalyzer(const ::zeek::file_analysis::Tag& tag) {
    return _file_analyzers_by_subtype[tag.Subtype()].parser;
}

#ifdef HAVE_PACKET_ANALYZERS
const spicy::rt::Parser* plugin::Zeek_Spicy::Plugin::parserForPacketAnalyzer(const ::zeek::packet_analysis::Tag& tag) {
    return _packet_analyzers_by_subtype[tag.Subtype()].parser;
}
#endif

::zeek::analyzer::Tag plugin::Zeek_Spicy::Plugin::tagForProtocolAnalyzer(const ::zeek::analyzer::Tag& tag) {
    if ( auto r = _protocol_analyzers_by_subtype[tag.Subtype()].replaces )
        return r;
    else
        return tag;
}

::zeek::analyzer::Tag plugin::Zeek_Spicy::Plugin::tagForFileAnalyzer(const ::zeek::analyzer::Tag& tag) {
    // Don't have a replacement mechanism currently.
    return tag;
}

#ifdef HAVE_PACKET_ANALYZERS
::zeek::analyzer::Tag plugin::Zeek_Spicy::Plugin::tagForPacketAnalyzer(const ::zeek::analyzer::Tag& tag) {
    // Don't have a replacement mechanism currently.
    return tag;
}
#endif

::zeek::plugin::Configuration plugin::Zeek_Spicy::Plugin::Configure() {
    ::zeek::plugin::Configuration config;
    config.name = "_Zeek::Spicy"; // Prefix with underscore to make sure it gets loaded first
    config.description = "Support for Spicy parsers (*.spicy, *.evt, *.hlto)";
    config.version.major = PROJECT_VERSION_MAJOR;
    config.version.minor = PROJECT_VERSION_MINOR;
    config.version.patch = PROJECT_VERSION_PATCH;

    EnableHook(::zeek::plugin::HOOK_LOAD_FILE);

    return config;
}

void plugin::Zeek_Spicy::Plugin::InitPreScript() {
    zeek::plugin::Plugin::InitPreScript();

    ZEEK_DEBUG("Beginning pre-script initialization");

    if ( auto opts = getenv("SPICY_PLUGIN_OPTIONS") ) {
        if ( auto rc = Driver::parseOptionsPreScript(opts); ! rc )
            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error parsing SPICY_PLUGIN_OPTIONS, %s", rc.error()));
    }

    if ( auto dir = getenv("ZEEK_SPICY_PATH") )
        addLibraryPaths(dir);

    addLibraryPaths(hilti::rt::normalizePath(OurPlugin->PluginDirectory()).string() + "/spicy");
    autoDiscoverModules();

    ZEEK_DEBUG("Beginning pre-script initialization");
}

// Returns a port's Zeek-side transport protocol.
static ::TransportProto transport_protocol(const hilti::rt::Port port) {
    switch ( port.protocol() ) {
        case hilti::rt::Protocol::TCP: return ::TransportProto::TRANSPORT_TCP;
        case hilti::rt::Protocol::UDP: return ::TransportProto::TRANSPORT_UDP;
        case hilti::rt::Protocol::ICMP: return ::TransportProto::TRANSPORT_ICMP;
        default:
            reporter::internalError(
                hilti::rt::fmt("unsupported transport protocol in port '%s' for Zeek conversion", port));
            return ::TransportProto::TRANSPORT_UNKNOWN;
    }
}

void plugin::Zeek_Spicy::Plugin::InitPostScript() {
    zeek::plugin::Plugin::InitPostScript();

    ZEEK_DEBUG("Beginning post-script initialization");

    for ( auto p : _driver->driverOptions().inputs ) {
        ZEEK_DEBUG(hilti::rt::fmt("Loading input file %s", p));
        if ( auto rc = _driver->loadFile(p); ! rc )
            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error loading %s: %s", p, rc.error().description()));
    }

    {
        // Compile all the inputs.
        ZEEK_DEBUG("Compiling input files");
        hilti::logging::DebugPushIndent _(debug::ZeekPlugin);

        if ( auto rc = _driver->compile(); ! rc ) {
            if ( rc.error().context().size() )
                // Don't have a good way to report multi-line output.
                std::cerr << rc.error().context() << std::endl;

            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error during compilation: %s", rc.error().description()));
        }

        if ( ! _driver->driverOptions().output_path.empty() )
            // If an output path is set, we're in precompilation mode, just exit.
            exit(0);

        // If there are errors, compile() should have flagged that through its
        // exit code.
        assert(hilti::logger().errors() == 0);
    }

    // Init runtime, which will trigger all initialization code to execute.
    ZEEK_DEBUG("Initializing Spicy runtime");

    auto config = hilti::rt::configuration::get();

    if ( ::zeek::id::find_const("Spicy::enable_print")->AsBool() ) //NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
        config.cout = std::cout;
    else
        config.cout.reset();

    config.abort_on_exceptions = ::zeek::id::find_const("Spicy::abort_on_exceptions")->AsBool();
    config.show_backtraces = ::zeek::id::find_const("Spicy::show_backtraces")->AsBool();

    hilti::rt::configuration::set(config);

    try {
        hilti::rt::init();
        spicy::rt::init();
    } catch ( const hilti::rt::Exception& e ) {
        std::cerr << hilti::rt::fmt("uncaught runtime exception %s during initialization: %s",
                                    hilti::rt::demangle(typeid(e).name()), e.what())
                  << std::endl;
        exit(1);
    } catch ( const std::runtime_error& e ) {
        std::cerr << hilti::rt::fmt("uncaught C++ exception %s during initialization: %s",
                                    hilti::rt::demangle(typeid(e).name()), e.what())
                  << std::endl;
        exit(1);
    }

    // Fill in the parser information now that we derived from the ASTs.
    auto find_parser = [](const std::string& analyzer, const std::string& parser) -> const spicy::rt::Parser* {
        if ( parser.empty() )
            return nullptr;

        for ( auto p : spicy::rt::parsers() ) {
            if ( p->name == parser )
                return p;
        }

        reporter::internalError(
            hilti::rt::fmt("Unknown Spicy parser '%s' requested by analyzer '%s'", parser, analyzer));
        return nullptr; // cannot be reached
    };

    for ( auto& p : _protocol_analyzers_by_subtype ) {
        ZEEK_DEBUG(hilti::rt::fmt("Registering %s protocol analyzer %s with Zeek", p.protocol, p.name_analyzer));

        p.parser_orig = find_parser(p.name_analyzer, p.name_parser_orig);
        p.parser_resp = find_parser(p.name_analyzer, p.name_parser_resp);

        if ( p.name_replaces.size() ) {
            ZEEK_DEBUG(hilti::rt::fmt("  Replaces existing protocol analyzer %s", p.name_replaces));
            p.replaces = ::zeek::analyzer_mgr->GetAnalyzerTag(p.name_replaces.c_str());

            if ( ! p.replaces )
                reporter::error(hilti::rt::fmt("Parser '%s' is to replace '%s', but that one does not exist",
                                               p.name_analyzer, p.name_replaces));
        }

        ::zeek::analyzer::Component::factory_callback factory = nullptr;

        switch ( p.protocol ) {
            case hilti::rt::Protocol::TCP: factory = spicy::zeek::rt::TCP_Analyzer::InstantiateAnalyzer; break;

            case hilti::rt::Protocol::UDP: factory = spicy::zeek::rt::UDP_Analyzer::InstantiateAnalyzer; break;

            default: reporter::error("unsupported protocol in analyzer"); return;
        }

        auto c = new ::zeek::analyzer::Component(p.name_analyzer, factory, p.subtype);
        AddComponent(c);

        // Hack to prevent Zeekygen fromp reporting the ID as not having a
        // location during the following initialization step.
        ::zeek::detail::zeekygen_mgr->Script("<Spicy>");
        ::zeek::detail::set_location(::zeek::detail::Location("<Spicy>", 0, 0, 0, 0));

        // TODO(robin): Should Zeek do this? It has run component intiialization at
        // this point already, so ours won't get initialized anymore.
        c->Initialize();

        // Register analyzer for its well-known ports.
        auto tag = ::zeek::analyzer_mgr->GetAnalyzerTag(p.name_analyzer.c_str());
        if ( ! tag )
            reporter::internalError(hilti::rt::fmt("cannot get analyzer tag for '%s'", p.name_analyzer));

        for ( auto port : p.ports ) {
            ZEEK_DEBUG(hilti::rt::fmt("  Scheduling analyzer for port %s", port));
            ::zeek::analyzer_mgr->RegisterAnalyzerForPort(tag, transport_protocol(port), port.port());
        }

        if ( p.parser_resp ) {
            for ( auto port : p.parser_resp->ports ) {
                if ( port.direction != spicy::rt::Direction::Both && port.direction != spicy::rt::Direction::Responder )
                    continue;

                ZEEK_DEBUG(hilti::rt::fmt("  Scheduling analyzer for port %s", port.port));
                ::zeek::analyzer_mgr->RegisterAnalyzerForPort(tag, transport_protocol(port.port), port.port.port());
            }
        }
    }

    for ( auto& p : _file_analyzers_by_subtype ) {
        ZEEK_DEBUG(hilti::rt::fmt("Registering file analyzer %s with Zeek", p.name_analyzer.c_str()));

        p.parser = find_parser(p.name_analyzer, p.name_parser);

        auto c = new ::zeek::file_analysis::Component(p.name_analyzer,
                                                      ::spicy::zeek::rt::FileAnalyzer::InstantiateAnalyzer, p.subtype);
        AddComponent(c);

        // Hack to prevent Zeekygen from reporting the ID as not having a
        // location during the following initialization step.
        ::zeek::detail::zeekygen_mgr->Script("<Spicy>");
        ::zeek::detail::set_location(::zeek::detail::Location("<Spicy>", 0, 0, 0, 0));

        // TODO: Should Zeek do this? It has run component intiialization at
        // this point already, so ours won't get initialized anymore.
        c->Initialize();

        // Register analyzer for its MIME types.
        auto tag = ::zeek::file_mgr->GetComponentTag(p.name_analyzer.c_str());
        if ( ! tag )
            reporter::internalError(hilti::rt::fmt("cannot get analyzer tag for '%s'", p.name_analyzer));

        auto register_analyzer_for_mime_type = [&](auto tag, const std::string& mt) {
            ZEEK_DEBUG(hilti::rt::fmt("  Scheduling analyzer for MIME type %s", mt));

            // MIME types are registered in scriptland, so we'll raise an
            // event that will do it for us through a predefined handler.
            zeek::Args vals = ::spicy::zeek::compat::ZeekArgs_New();
            ::spicy::zeek::compat::ZeekArgs_Append(vals, ::spicy::zeek::compat::FileAnalysisComponentTag_AsVal(tag));
            ::spicy::zeek::compat::ZeekArgs_Append(vals, ::spicy::zeek::compat::StringVal_New(
                                                             mt)); //NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
            ::zeek::EventHandlerPtr handler =
                ::spicy::zeek::compat::event_register_Register("spicy_analyzer_for_mime_type");
            ::spicy::zeek::compat::event_mgr_Enqueue(handler, vals);
        };

        for ( auto mt : p.mime_types )
            register_analyzer_for_mime_type(tag, mt);

        if ( p.parser ) {
            for ( auto mt : p.parser->mime_types )
                register_analyzer_for_mime_type(tag, mt);
        }
    }

#ifdef HAVE_PACKET_ANALYZERS
    for ( auto& p : _packet_analyzers_by_subtype ) {
        ZEEK_DEBUG(hilti::rt::fmt("Registering packet analyzer %s with Zeek", p.name_analyzer.c_str()));

        p.parser = find_parser(p.name_analyzer, p.name_parser);

        auto instantiate = [p]() -> ::zeek::packet_analysis::AnalyzerPtr {
            return ::spicy::zeek::rt::PacketAnalyzer::Instantiate(p.name_analyzer);
        };
        auto c = new ::zeek::packet_analysis::Component(p.name_analyzer, instantiate, p.subtype);
        AddComponent(c);

        // Hack to prevent Zeekygen from reporting the ID as not having a
        // location during the following initialization step.
        ::zeek::detail::zeekygen_mgr->Script("<Spicy>");
        ::zeek::detail::set_location(::zeek::detail::Location("<Spicy>", 0, 0, 0, 0));

        // TODO: Should Zeek do this? It has run component intiialization at
        // this point already, so ours won't get initialized anymore.
        c->Initialize();
    }
#endif

    ZEEK_DEBUG("Done with post-script initialization");
}


void plugin::Zeek_Spicy::Plugin::Done() {
    ZEEK_DEBUG("Shutting down Spicy runtime");
    spicy::rt::done();
    hilti::rt::done();
}

void plugin::Zeek_Spicy::Plugin::loadModule(const hilti::rt::filesystem::path& path) {
    try {
        ZEEK_DEBUG(hilti::rt::fmt("Loading %s", path.native()));

        if ( auto [library, inserted] = _libraries.insert({path, hilti::rt::Library(path)}); inserted ) {
            if ( auto load = library->second.open(); ! load )
                hilti::rt::fatalError(hilti::rt::fmt("could not open library path %s: %s", path, load.error()));
        }
    } catch ( const hilti::rt::EnvironmentError& e ) {
        hilti::rt::fatalError(e.what());
    }
}

int plugin::Zeek_Spicy::Plugin::HookLoadFile(const LoadType type, const std::string& file,
                                             const std::string& resolved) {
    auto ext = hilti::rt::filesystem::path(file).extension();

    if ( ext == ".spicy" || ext == ".evt" || ext == ".hlt" || ext == ".hlto" ) {
        ZEEK_DEBUG(hilti::rt::fmt("Loading input file '%s'", file));
        if ( auto rc = _driver->loadFile(file); ! rc ) {
            spicy::zeek::reporter::fatalError(hilti::rt::fmt("error loading %s: %s", file, rc.error().description()));
            return 0;
        }

        return 1;
    }

    if ( ext == ".hlto" ) {
        loadModule(file);
        return 1;
    }

    if ( ext == ".spicy" || ext == ".evt" || ext == ".hlt" )
        reporter::fatalError(hilti::rt::fmt("cannot load '%s', Spicy plugin was not compiled with JIT support", file));

    return -1;
}

void plugin::Zeek_Spicy::Plugin::autoDiscoverModules() {
    const char* search_paths = getenv("SPICY_MODULE_PATH");

    if ( ! search_paths )
        search_paths = spicy::zeek::configuration::PluginModuleDirectory;

    for ( auto dir : hilti::rt::split(search_paths, ":") ) {
        std::string pattern = hilti::rt::filesystem::path(hilti::rt::trim(dir)) / "*.hlto";
        ZEEK_DEBUG(hilti::rt::fmt("Searching for %s", pattern));

        glob_t gl;
        if ( glob(pattern.c_str(), 0, 0, &gl) == 0 ) {
            for ( size_t i = 0; i < gl.gl_pathc; i++ )
                loadModule(gl.gl_pathv[i]);

            globfree(&gl);
        }
    }
}
