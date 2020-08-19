// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/types/port.h>

#include <spicy/rt/mime.h>

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/module.h>
#include <hilti/ast/type.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/driver.h>

#include <spicy/ast/declarations/unit-hook.h>

#include "driver.h"

namespace spicy::rt {
struct Parser;
}

namespace spicy::zeek {

namespace glue {

/** Representation of a Spicy protocol analyzer, parsed from an EVT file. */
struct ProtocolAnalyzer {
    // Information parsed directly from the *.evt file.
    hilti::Location location;                                  /**< Location where the analyzer was defined. */
    hilti::ID name;                                            /**< Name of the analyzer. */
    hilti::rt::Protocol protocol = hilti::rt::Protocol::Undef; /**< The transport layer the analyzer uses. */
    std::vector<hilti::rt::Port> ports;                        /**< The ports associated with the analyzer. */
    hilti::ID unit_name_orig; /**< The fully-qualified name of the unit type to parse the originator side. */
    hilti::ID unit_name_resp; /**< The fully-qualified name of the unit type to parse the originator side. */
    std::string replaces;     /**< Name of another analyzer this one replaces. */

    // Computed information.
    std::optional<UnitInfo> unit_orig; /**< The type of the unit to parse the originator side. */
    std::optional<UnitInfo> unit_resp; /**< The type of the unit to parse the originator side. */
};

/** Representation of a Spicy file analyzer, parsed from an EVT file. */
struct FileAnalyzer {
    // Information parsed directly from the *.evt file.
    hilti::Location location;            /**< Location where the analyzer was defined. */
    hilti::ID name;                      /**< Name of the analyzer. */
    std::vector<std::string> mime_types; /**< The mime_types associated with the analyzer. */
    hilti::ID unit_name;                 /**< The fully-qualified name of the unit type to parse with. */

    // Computed information.
    std::optional<UnitInfo> unit; /**< The type of the unit to parse the originator side. */
};

/**
 * Representation of an expression computing the value of a parameter passed
 * to Spicy-generated events.
 */
struct ExpressionAccessor {
    // Information parsed directly from the *.evt file.
    int nr;                   /**< Position of this expression in argument list. */
    std::string expression;   /**< The original string representation of the expression. */
    hilti::Location location; /**< Location where the expression was defined. */
};

/** Representation of a compiled Spicy module. */
struct SpicyModule {
    // Provided.
    hilti::ID id;                         /**< Name of the module */
    std::filesystem::path file;           /**< The path the module was read from. */
    std::set<std::filesystem::path> evts; /**< EVT files that refer to this module. */

    // Generated code.
    std::optional<hilti::Module> spicy_module; /**< the ``BroHooks_*.spicy`` module. */
};

/** Representation of an event parsed from an EVT file. */
struct Event {
    // Information parsed directly from the *.evt file.
    std::filesystem::path file;     /**< The path of the *.evt file we parsed this from. */
    hilti::ID name;                 /**< The name of the event. */
    hilti::ID path;                 /**< The hook path as specified in the evt file. */
    std::string condition;          /**< Condition that must be true for the event to trigger. */
    std::vector<std::string> exprs; /**< The argument expressions. */
    int priority;                   /**< Event/hook priority. */
    hilti::Location location;       /**< Location where event is defined. */

    // Computed information.
    hilti::ID hook;                             /**< The name of the hook triggering the event. */
    hilti::ID unit;                             /**< The fully qualified name of the unit type. */
    std::optional<spicy::type::Unit> unit_type; /**< The Spicy type of referenced unit. */
    hilti::ID unit_module_id;                   /**< The name of the module the referenced unit is defined in. */
    std::filesystem::path unit_module_path;     /**< The path of the module that the referenced unit is defined in. */
    std::shared_ptr<glue::SpicyModule>
        spicy_module; /**< State for the Spichy module the referenced unit is defined in. */

    // TODO: The following aren't set yet.

    // Code generation.
    std::optional<spicy::declaration::UnitHook> spicy_hook;  /**< The generated Spicy hook. */
    std::optional<hilti::declaration::Function> hilti_raise; /**< The generated HILTI raise() function. */
    std::vector<ExpressionAccessor> expression_accessors; /**< One HILTI function per expression to access the value. */
};

} // namespace glue

/** Generates the glue code between Zeek and Spicy based on *.evt files. */
class GlueCompiler {
public:
    /** Constructor. */
    GlueCompiler(Driver* driver, int zeek_version);

    /** Destructor. */
    ~GlueCompiler();

    /** Parses an `*.evt` file, without generating any code yet. */
    bool loadEvtFile(std::filesystem::path& path);

    /**
     * Registers a Spicy file to generate glue code for, without generating
     * any code yet.
     *
     * @param id ID of the module
     * @param file path the module is loaded from
     */
    void addSpicyModule(const hilti::ID& id, const std::filesystem::path& file);

    /**
     * Generates all glue code based on previously registered `*.evt` and
     * Spicy files.
     */
    bool compile();

private:
    /**
     * Filters input EVT file by applying preprocessor directives.
     */
    void preprocessEvtFile(std::filesystem::path& path, std::istream& in, std::ostream& out);

    /**
     * Extracts the next semicolon-terminated block from an input stream,
     * accounting for special EVT constructs like strings and comments.
     *
     * @param in stream to read from
     * @param lineno pointer to integer that will be increased with line breaks
     * @return the read block of data, with comments removed, and empty if end of
     * data has been reached; error will be set if parsing failed
     */
    hilti::Result<std::string> getNextEvtBlock(std::istream& in, int* lineno) const;

    // Parsers for parts from EVT files.
    glue::ProtocolAnalyzer parseProtocolAnalyzer(const std::string& chunk);
    glue::FileAnalyzer parseFileAnalyzer(const std::string& chunk);
    glue::Event parseEvent(const std::string& chunk);

    /** Computes the missing pieces for all `Event` instances.  */
    bool PopulateEvents();

    /**
     * Create the Spicy hook for an event that triggers a corresponding Zeek
     * event.
     */
    bool CreateSpicyHook(glue::Event* ev);

    /** Returns a HILTI string expression with the location of the event. */
    hilti::Expression location(const glue::Event& ev);

    /** Returns a HILTI string expression with the location of the event. */
    hilti::Expression location(const glue::ExpressionAccessor& e);

    Driver* _driver;
    int _zeek_version;
    std::map<hilti::ID, std::shared_ptr<glue::SpicyModule>> _spicy_modules;

    std::vector<std::pair<ID, std::optional<ID>>> _imports;  /**< imports from EVT file, with ID and optional scope */
    std::vector<glue::Event> _events;                        /**< events parsed from EVT files */
    std::vector<glue::ProtocolAnalyzer> _protocol_analyzers; /**< protocol analyzers parsed from EVT files */
    std::vector<glue::FileAnalyzer> _file_analyzers;         /**< file analyzers parsed from EVT files */

    std::vector<hilti::Location> _locations; /**< location stack during parsing EVT files */
};
} // namespace spicy::zeek
