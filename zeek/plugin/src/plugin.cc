// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>

#include <exception>

#include <hilti/rt/autogen/version.h>
#include <hilti/rt/configuration.h>
#include <hilti/rt/init.h>
#include <hilti/rt/library.h>
#include <hilti/rt/types/vector.h>

#include <spicy/rt/init.h>
#include <spicy/rt/parser.h>

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/file-analyzer.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/protocol-analyzer.h>
#include <zeek-spicy/zeek-compat.h>
#include <zeek-spicy/zeek-reporter.h>

#ifndef ZEEK_HAVE_JIT
plugin::Zeek_Spicy::Plugin SpicyPlugin;
plugin::Zeek_Spicy::Plugin* plugin::Zeek_Spicy::OurPlugin = &SpicyPlugin;
#endif

using namespace spicy::zeek;

#ifndef ZEEK_HAVE_JIT
void spicy::zeek::debug::do_log(const std::string_view& msg) { HILTI_RT_DEBUG("zeek", msg); }
#endif

plugin::Zeek_Spicy::Plugin::Plugin() {}

plugin::Zeek_Spicy::Plugin::~Plugin() {}

void plugin::Zeek_Spicy::Plugin::addLibraryPaths(const std::string& dirs) {
    for ( const auto& dir : hilti::rt::split(dirs, ":") )
        ::zeek::util::detail::add_to_zeek_path(std::string(dir)); // Add to Zeek's search path.
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

::zeek::plugin::Configuration plugin::Zeek_Spicy::Plugin::Configure() {
    ::zeek::plugin::Configuration config;
    config.name = "_Zeek::Spicy"; // Prefix with underscore to make sure it gets loaded first
#ifdef ZEEK_HAVE_JIT
    config.description = "Support for Spicy parsers (*.spicy, *.evt, *.hlto)";
#else
    config.description = "Support for Spicy parsers (*.hlto)";
#endif
    config.version.major = PROJECT_VERSION_MAJOR;
    config.version.minor = PROJECT_VERSION_MINOR;
    config.version.patch = PROJECT_VERSION_PATCH;

    EnableHook(::zeek::plugin::HOOK_LOAD_FILE);

    return config;
}

void plugin::Zeek_Spicy::Plugin::InitPreScript() {
    ZEEK_DEBUG("Beginning pre-script initialization (runtime)");

    if ( auto dir = getenv("ZEEK_SPICY_PATH") )
        addLibraryPaths(dir);

    addLibraryPaths(hilti::rt::normalizePath(OurPlugin->PluginDirectory()).string() + "/spicy");

    ZEEK_DEBUG("Beginning pre-script initialization (runtime)");
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
    ZEEK_DEBUG("Beginning post-script initialization (runtime)");

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

        // TODO(robin): Should Bro do this? It has run component intiialization at
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

        // TODO: Should Bro do this? It has run component intiialization at
        // this point already, so ours won't get initialized anymore.
        c->Initialize();

        // Register analyzer for its MIME types.
        auto tag = ::zeek::file_mgr->GetComponentTag(p.name_analyzer.c_str());
        if ( ! tag )
            reporter::internalError(hilti::rt::fmt("cannot get analyzer tag for '%s'", p.name_analyzer));

        for ( auto mt : p.mime_types ) {
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
        }
    }

    ZEEK_DEBUG("Done with post-script initialization (runtime)");
}


void plugin::Zeek_Spicy::Plugin::Done() {
    ZEEK_DEBUG("Shutting down Spicy runtime");
    spicy::rt::done();
    hilti::rt::done();
}

int plugin::Zeek_Spicy::Plugin::HookLoadFile(const LoadType type, const std::string& file,
                                             const std::string& resolved) {
    auto ext = std::filesystem::path(file).extension();

    if ( ext == ".hlto" ) {
        try {
            if ( ! _libraries.count(file) ) {
                _libraries.insert({file, hilti::rt::Library(file)});
                if ( auto load = _libraries.at(file).open(); ! load )
                    hilti::rt::fatalError(hilti::rt::fmt("could not open library file %s: %s", file, load.error()));
            }
        } catch ( const hilti::rt::EnvironmentError& e ) {
            hilti::rt::fatalError(e.what());
        }

        return 1;
    }

    if ( ext == ".spicy" || ext == ".evt" || ext == ".hlt" )
        reporter::fatalError(hilti::rt::fmt("cannot load '%s', Spicy plugin was not compiled with JIT support", file));

    return -1;
}
