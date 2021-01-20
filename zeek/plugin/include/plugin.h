// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <hilti/rt/library.h>
#include <hilti/rt/types/port.h>

#include <zeek-spicy/zeek-compat.h>

#ifdef HAVE_TOOLCHAIN
#include <zeek-spicy/driver.h>
#endif

namespace spicy::rt {
struct Parser;
}

namespace plugin::Zeek_Spicy {

/*
 * Dynamic Zeek plugin. This class does not implement any JIT compilation.
 * For that, we have a separate PluginJIT that derives from this one.
 *
 */
class Plugin : public zeek::plugin::Plugin {
public:
    Plugin();
    virtual ~Plugin();

    /**
     * Runtime method to register a protocol analyzer with its Zeek-side
     * configuration. This is called at startup by generated Spicy code for
     * each protocol analyzer defined in an EVT file.
     *
     * @param name name of the analyzer as defined in its EVT file
     * @param proto analyzer's transport-layer protocol
     * @param prts well-known ports for the analyzer; it'll be activated automatically for these
     * @param parser_orig name of the Spicy parser for the originator side; must match the name that Spicy registers the
     * unit's parser with
     * @param parser_resp name of the Spicy parser for the originator side; must match the name that Spicy registers the
     * unit's parser with
     * @param replaces optional name of existing Zeek analyzder that this one replaces; the Zeek analyzer will
     * automatically be disabled
     */
    void registerProtocolAnalyzer(const std::string& name, hilti::rt::Protocol proto,
                                  const hilti::rt::Vector<hilti::rt::Port>& ports, const std::string& parser_orig,
                                  const std::string& parser_resp, const std::string& replaces = "");

    /**
     * Runtime method to register a file analyzer with its Zeek-side
     * configuration. This is called at startup by generated Spicy code for
     * each file analyzer defined in an EVT file
     *
     * @param name name of the analyzer as defined in its EVT file
     * @param mime_types list of MIME types the analyzer handles; it'll be automatically used for all files of matching
     * types
     * @param parser name of the Spicy parser for parsing the file; must match the name that Spicy registers the unit's
     * parser with
     */
    void registerFileAnalyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                              const std::string& parser);

    /**
     * Runtime method to register a packet analyzer with its Zeek-side
     * configuration. This is called at startup by generated Spicy code for
     * each packet analyzer defined in an EVT file.
     *
     * @param name name of the analyzer as defined in its EVT file
     * @param parser name of the Spicy parser for parsing the packet; must
     * match the name that Spicy registers the unit's
     * parser with.
     */
    void registerPacketAnalyzer(const std::string& name,
                                const std::string& parser);

    /** TODO */
    void registerEnumType(const std::string& ns, const std::string& id,
                          const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels);

    /**
     * Runtime method to retrieve the Spicy parser for a given Zeek protocol analyzer tag.
     *
     * @param analyzer requested protocol analyzer
     * @param is_orig true if requesting the parser parser for a sessions' originator side, false for the responder
     * @return parser, or null if we don't have one for this tag. The pointer will remain valid for the life-time of the
     * process.
     */
    const spicy::rt::Parser* parserForProtocolAnalyzer(const ::zeek::analyzer::Tag& tag, bool is_orig);

    /**
     * Runtime method to retrieve the Spicy parser for a given Zeek file analyzer tag.
     *
     * @param analyzer requested file analyzer.
     * @return parser, or null if we don't have one for this tag. The pointer will remain valid for the life-time of the
     * process.
     */
    const spicy::rt::Parser* parserForFileAnalyzer(const ::zeek::file_analysis::Tag& tag);

#ifdef HAVE_PACKET_ANALYZERS
    /**
     * Runtime method to retrieve the Spicy parser for a given Zeek packet analyzer tag.
     *
     * @param analyzer requested packet analyzer.
     * @return parser, or null if we don't have one for this tag. The pointer will remain
     * valid for the life-time of the process.
     */
    const spicy::rt::Parser* parserForPacketAnalyzer(const ::zeek::packet_analysis::Tag& tag);
#endif

    /**
     * Runtime method to retrieve the analyzer tag that should be passed to
     * script-land when talking about a protocol analyzer. This is normally
     * the analyzer's standard tag, but may be replaced with somethign else
     * if the analyzer substitutes for an existing one.
     *
     * @param tag original tag we query for how to pass it to script-land.
     * @return desired tag for passing to script-land.
     */
    ::zeek::analyzer::Tag tagForProtocolAnalyzer(const ::zeek::analyzer::Tag& tag);

    /**
     * Runtime method to retrieve the analyzer tag that should be passed to
     * script-land when talking about a file analyzer. This is normally the
     * analyzer's standard tag, but may be replaced with somethign else if
     * the analyzer substitutes for an existing one.
     *
     * @param tag original tag we query for how to pass it to script-land.
     * @return desired tag for passing to script-land.
     */
    ::zeek::analyzer::Tag tagForFileAnalyzer(const ::zeek::analyzer::Tag& tag);

#ifdef HAVE_PACKET_ANALYZERS
    /**
     * Runtime method to retrieve the analyzer tag that should be passed to
     * script-land when talking about a packet analyzer. This is normally the
     * analyzer's standard tag, but may be replaced with something else if
     * the analyzer substitutes for an existing one.
     *
     * @param tag original tag we query for how to pass it to script-land.
     * @return desired tag for passing to script-land.
     */
    ::zeek::analyzer::Tag tagForPacketAnalyzer(const ::zeek::analyzer::Tag& tag);
#endif

protected:
    /**
     * Adds one or more paths to search for *.spicy modules. The path will be
     * passed to the compiler. Note that this must be called only before
     * InitPreScripts().
     *
     * @param paths The directories to search. Multiple directories can be
     * given at once by separating them with a colon.
     */
    virtual void addLibraryPaths(const std::string& dirs);

    // Overriding method from Zeek's plugin API.
    zeek::plugin::Configuration Configure() override;

    // Overriding method from Zeek's plugin API.
    void InitPreScript() override;

    // Overriding method from Zeek's plugin API.
    void InitPostScript() override;

    // Overriding method from Zeek's plugin API.
    void Done() override;

    // Overriding method from Zeek's plugin API.
    int HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved) override;

private:
    // Load one *.hlto module.
    void loadModule(const hilti::rt::filesystem::path& path);

    // Search SPICY_MODULE_PATH for pre-compiled *.hlto modules and load them.
    void autoDiscoverModules();

    /** Captures a registered protocol analyzer. */
    struct ProtocolAnalyzerInfo {
        // Filled in when registering the analyzer.
        std::string name_analyzer;
        std::string name_parser_orig;
        std::string name_parser_resp;
        std::string name_replaces;
        hilti::rt::Protocol protocol = hilti::rt::Protocol::Undef;
        hilti::rt::Vector<hilti::rt::Port> ports;
        ::zeek::analyzer::Tag::subtype_t subtype;

        // Filled in during InitPostScript().
        const spicy::rt::Parser* parser_orig;
        const spicy::rt::Parser* parser_resp;
        ::zeek::analyzer::Tag replaces;
    };

    /** Captures a registered file analyzer. */
    struct FileAnalyzerInfo {
        // Filled in when registering the analyzer.
        std::string name_analyzer;
        std::string name_parser;
        hilti::rt::Vector<std::string> mime_types;
        ::zeek::analyzer::Tag::subtype_t subtype;

        // Filled in during InitPostScript().
        const spicy::rt::Parser* parser;
    };

#ifdef HAVE_PACKET_ANALYZERS
    /** Captures a registered file analyzer. */
    struct PacketAnalyzerInfo {
        // Filled in when registering the analyzer.
        std::string name_analyzer;
        std::string name_parser;
        ::zeek::packet_analysis::Tag::subtype_t subtype;

        // Filled in during InitPostScript().
        const spicy::rt::Parser* parser;
    };
#endif

    std::vector<ProtocolAnalyzerInfo> _protocol_analyzers_by_subtype;
    std::vector<FileAnalyzerInfo> _file_analyzers_by_subtype;
#ifdef HAVE_PACKET_ANALYZERS
    std::vector<PacketAnalyzerInfo> _packet_analyzers_by_subtype;
#endif
    std::unordered_map<std::string, hilti::rt::Library> _libraries;

#ifdef HAVE_TOOLCHAIN
    std::unique_ptr<Driver> _driver;
#endif
};

// Will be initalized to point to whatever type of plugin is instantiated.
extern Plugin* OurPlugin;

} // namespace plugin::Zeek_Spicy

extern plugin::Zeek_Spicy::Plugin SpicyPlugin;
