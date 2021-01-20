// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <spicy/compiler/driver.h>

namespace spicy::zeek {

class GlueCompiler;

/**
 * Captures meta information about a Spicy unit type, derived from its AST.
 */
struct UnitInfo {
    hilti::ID id;                            /**< fully-qualified name of the unit type */
    hilti::Type type;                        /**< the unit's type. */
    hilti::ID module_id;                     /**< name of module unit is defined in */
    hilti::rt::filesystem::path module_path; /**< path of mpdule that unit is defined in */
};

/**
 * Captures meta information about an public Spicy enum type, derived from its AST.
 */
struct EnumInfo {
    hilti::ID id;                            /**< fully-qualified name of the enum type */
    hilti::Type type;                        /**< the enum's type. */
    hilti::ID module_id;                     /**< name of module enum is defined in */
    hilti::rt::filesystem::path module_path; /**< path of mpdule that enum is defined in */
};

/** Spicy compilation driver. */
class Driver : public spicy::Driver {
public:
    /** Constructor. */
    Driver(const std::string& argv0, int zeek_version);

    /** Destructor. */
    ~Driver();

    /**
     * Schedules an *.spicy, *.evt, or *.hlt file for loading. Note that it
     * won't necessarily load them all immediately, but may queue some for
     * later processing.
     *
     * @param file file to load, which will be searched across all current search paths
     * @param relative_to if given, relative paths will be interpreted as relative to this directory
     */
    hilti::Result<hilti::Nothing> loadFile(hilti::rt::filesystem::path file,
                                           const hilti::rt::filesystem::path& relative_to = {});

    /**
     * After user scripts have been read, compiles and links all resulting
     * Spicy code. Note that compielr and driver options must have been set
     * before calling this.
     *
     * Must be called before any packet processing starts.
     *
     * @return False if an error occured. It will have been reported already.
     */
    hilti::Result<hilti::Nothing> compile();

    /**
     * Returns a meta information for unit type. The Spicy module defining
     * the unit must have been compiled already for it to be found.
     *
     * @param fully qualified name of unit to look up
     * @return meta data, or an error if the type is not (yet) known
     */
    hilti::Result<UnitInfo> lookupUnit(const hilti::ID& unit);

    /**
     * Returns a vector of all enum types with public linkage.The Spicy
     * module defining the unit must have been compiled already to return
     * something.
     */
    const std::vector<EnumInfo>& publicEnumTypes() { return _enums; }

    /**
     * Parses some options command-line style *before* Zeek-side scripts have
     * been processed. Most of the option processing happens in
     * `parseOptionsPostScript()` instead, except for things that must be in
     * place already before script processing.
     *
     * @param options space-separated string of command line argument to parse
     * @return success if all argument could be parsed, or a suitable error message
     */
    static hilti::Result<hilti::Nothing> parseOptionsPreScript(const std::string& options);

    /**
     * Parses options command-line style after Zeek-side scripts have been
     * fully procssed. Most of the option processing happens here (vs. in
     * `parseOptionsPreScript()`) except for things that must be in place
     * already before script processing.
     *
     * @param options space-separated string of command line argument to parse
     * @param driver_options instance of options to update per parsed arguments
     * @param compiler_options instance of options to update per parsed arguments
     * @return success if all argument could be parsed, or a suitable error message
     */
    static hilti::Result<hilti::Nothing> parseOptionsPostScript(const std::string& options,
                                                                hilti::driver::Options* driver_options,
                                                                hilti::Options* compiler_options);

    /** Prints a usage message for options supported by `parseOptions{Pre,Post}Script()`. */
    static void usage(std::ostream& out);

protected:
    /**
     * Hook executed for all unit declarationss encountered in a Spicy
     * module. Derived classes may override this to add custom processing.
     *
     * @param e unit type's meta information
     */
    virtual void hookNewUnitType(const UnitInfo& e){};

    /**
     * Hook executed for all public enum declarations encountered in a Spicy
     * module. Derived classes may override this to add custom processing.
     *
     * @param e enum type's meta information
     */
    virtual void hookNewEnumType(const EnumInfo& e){};

    /** Overidden from HILTI driver. */
    void hookNewASTPreCompilation(const hilti::ID& id, const std::optional<hilti::rt::filesystem::path>& path,
                                  const hilti::Node& root) override;

    /** Overidden from HILTI driver. */
    void hookNewASTPostCompilation(const hilti::ID& id, const std::optional<hilti::rt::filesystem::path>& path,
                                   const hilti::Node& root) override;

    /** Overidden from HILTI driver. */
    hilti::Result<hilti::Nothing> hookCompilationFinished() override;

    /** Overidden from HILTI driver. */
    void hookInitRuntime() override;

    /** Overidden from HILTI driver. */
    void hookFinishRuntime() override;

    std::map<hilti::ID, UnitInfo> _units;
    std::vector<EnumInfo> _enums;

    std::unique_ptr<GlueCompiler> _glue;

    bool _need_glue = true; // true if glue code has not yet been generated
};

} // namespace spicy::zeek
