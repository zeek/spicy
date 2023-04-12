// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
// p

#pragma once

#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/unit.h>

namespace hilti {

class JIT;
struct Options;

namespace driver {

/** Enum to specify type of dependencies to output. */
enum class Dependencies {
    None, /**< No output of dependencies. */
    All,  /**< Output all other modules being depended on. */
    Code  /**< Output other modules being depended if they require separate compilation of their own to produce code. */
};

/**
 * Options for the compiler driver
 *
 * @note Only one of the `output_*` can be used at any time.
 */
struct Options {
    bool include_linker = false;    /**< if true, perform custom HILTI linker phase */
    bool output_hilti = false;      /**< render HILTI inputs back into HILTI source code */
    bool output_prototypes = false; /**< output C++ prototypes for generated code */
    bool output_cxx = false;        /**< output generated C++ code */
    std::string output_cxx_prefix;  /**< when outputting generated C++ code, prefix each module name with this string */
    bool output_linker = false;     /**< output generated HILTI linker C++ code */
    Dependencies output_dependencies = Dependencies::None; /**< output dependencies for compiled modules */
    bool execute_code = false;                             /**< compile code, and execute unless output_path is set */
    bool show_backtraces = false;                          /**< include backtraces when printing unhandled exceptions */
    bool abort_on_exceptions = false;                      /**< abort() instead of throwing HILTI exceptions */
    bool keep_tmps = false;                                /**< do not delete any temporary files created */
    bool skip_dependencies = false;                        /**< do not automatically compile dependencies during JIT */
    bool report_resource_usage = false; /**< print summary of runtime resource usage at termination */
    bool report_times = false;          /**< Report break-down of driver's execution time. */
    bool dump_code = false;             /**< Record all final HILTI and C++ code to disk for debugging. */
    bool global_optimizations = true;   /**< whether to run global HILTI optimizations on the generated code. */
    bool enable_profiling = false;      /**< Insert profiling instrumentation into generated C++ code */
    std::vector<hilti::rt::filesystem::path>
        inputs; /**< files to compile; these will be automatically pulled in by ``Driver::run()`` */
    hilti::rt::filesystem::path output_path; /**< file to store output in (default if empty is printing to stdout) */
    std::unique_ptr<Logger>
        logger; /**< `Logger` instances to use for diagnostics; set to a new logger by default by constructor */

    Options() { logger = std::make_unique<Logger>(); }
};

} // namespace driver

/**
 * Compiler driver.
 *
 * The driver is a high-level building block for writing command-line tools
 * compiling HILTI source files (and more). `hiltic` is just a tiny wrapper
 * around this class.
 *
 * Classes can drive from the driver to expand its functionality, including
 * for adding support for additional types of source files (e.g., Spicy
 * code).
 *
 */
class Driver {
public:
    /**
     * @param name descriptive name for the tool using the driver, which will
     * be used in usage and error messages.
     */
    explicit Driver(std::string name);

    /**
     * @param name descriptive name for the tool using the driver, which will
     * be used in usage and error messages.
     * @param argv0 the current executable, which will change the path's that
     * the global options instance returns if it's inside HILTI build
     * directory.
     */
    Driver(std::string name, const hilti::rt::filesystem::path& argv0);

    virtual ~Driver();

    Driver() = delete;
    Driver(const Driver&) = delete;
    Driver(Driver&&) noexcept = delete;
    Driver& operator=(const Driver&) = delete;
    Driver& operator=(Driver&&) noexcept = delete;

    /**
     * Frontend for parsing command line options into `driver::Options` and
     * `hilti::Options``. See the output of `hiltic --help` for a list.
     *
     * `setDriverOptions()` and `setCompilerOptions()` provide alternative
     * ways to set the options directly.
     *
     * @param argc,argv command line arguments to parse
     * @return set if successful; otherwise the result provides an error message
     */
    Result<Nothing> parseOptions(int argc, char** argv);

    /**
     * Schedules a unit for compilation. The driver will compile the unit once
     * `compile()` is called. If a module of the same ID or path has been added
     * previously, this will have no further effect.
     *
     * The `hookAddInput()` and `hookNewASTPreCompilation()` hooks will be
     * called immediately for the new module.
     *
     * @param u unit to schedule for compilation
     * @return set if successful; otherwise the result provides an error message
     */
    Result<Nothing> addInput(const std::shared_ptr<Unit>& u);

    /**
     * Schedules a source file for compilation. The file will be parsed
     * immediately, and then compiled later when `compile()` is called. If the
     * same source unit has been added previously, this method will have no
     * effect.
     *
     * The `hookAddInput()` and `hookNewASTPreCompilation()` hooks will be
     * called immediately for the new module.
     *
     * @param path source code to compile
     * @return set if successful; otherwise the result provides an error message
     */
    Result<Nothing> addInput(const hilti::rt::filesystem::path& path);

    /** Returns true if at least one input file has been added. */
    bool hasInputs() const {
        return ! (_pending_units.empty() && _processed_units.empty() && _processed_paths.empty() &&
                  _libraries.empty() && _external_cxxs.empty());
    }

    /** Returns the driver options currently in effect. */
    const auto& driverOptions() const { return _driver_options; }

    /** Returns the HILTI compiler options currently in effect. */
    const auto& hiltiOptions() const { return _compiler_options; }

    /**
     * Sets the driver's options and arguments.
     *
     * @param options the options
     */
    void setDriverOptions(driver::Options options);

    /**
     * Sets HILTI's compiler options.
     *
     * @param options the options
     */
    void setCompilerOptions(hilti::Options options);

    /**
     * Initializes the compilation process. Must be called after options have been set,
     * and before any inputs are added.
     *
     * @return set if successful; otherwise the result provides an error  message
     */
    Result<Nothing> initialize();

    /**
     * Loads, compiles, and links the source files. This must be called only
     * after driver and compiler options have been set. Internally, it chains
     * the various `*Modules()` methods.
     *
     * @return set if successful; otherwise the result provides an error message
     */
    Result<Nothing> compile();

    /**
     * Returns the current HILTI context. Valid only once compilation has
     * started, otherwise null.
     */
    const auto& context() const { return _ctx; }

    /** Shortcut to return the current context's options. */
    const auto& options() const { return _ctx->options(); }

    /**
     * Initializes HILTI's runtime system to prepare for execution of
     * compiled code. This will already trigger execution of all
     * module-specific initialization code (initialization of globals;
     * module-level statements). The method must be called only after
     * `compile()` has run already.
     *
     * @return set if successful; otherwise the result provides an error message
     */
    Result<Nothing> initRuntime();

    /**
     * Executes the `hilti_main` entry function in compiled code. This must
     * be called only after `initRuntime()` has run already.
     *
     * @return set if successful; otherwise the result provides an error message
     */
    Result<Nothing> executeMain();

    /**
     * Shuts down HILT's runtime library after execution has concluded,
     * cleaning up resources.
     *
     * @return set if successful; otherwise the result provides an error message
     */
    Result<Nothing> finishRuntime();

    /**
     * Compile and executes all source files. This is a convenience wrapper
     * around the stages of the process provided by other methods. It
     * executes all of `compile()`, `initRuntime()`, `executeMain()`, and
     * `finishRuntime()` in that order.
     *
     * @return set if successful; otherwise the result provides an error message
     */
    Result<Nothing> run();

protected:
    /**
     * Prints a usage message to stderr. The message summarizes the options
     * understood by `parseOptions()`.
     */
    void usage();

    /**
     * Compiles all registered input files to HILTI code.
     *
     * @return set if successful; otherwise the result provides an error  message
     */
    Result<Nothing> compileUnits();

    /**
     * Compiles all registered input files to C++ code.
     *
     * This function can only be invoked after `compileUnits`.
     *
     * @return set if successful; otherwise the result provides an error  message
     */
    Result<Nothing> codegenUnits();

    /**
     * Runs the HILTI-side linker on all available C++ code.
     *
     * @return set if successful; otherwise the result provides an error  message
     */
    Result<Nothing> linkUnits();

    /**
     * Writes out generated code if requested by driver options.
     *
     * @return set if successful; otherwise the result provides an error  message
     */
    Result<Nothing> outputUnits();

    /**
     * JIT all code compiled so far.
     *
     * @return set if successful; otherwise the result provides an error  message
     */
    Result<Nothing> jitUnits();

    /**
     * Helper function to create an `result::Error` with a message that
     * including driver name and, optionally, a file the error refers to.
     *
     * @param msg error message
     * @param p file to associate with the error, empty for none
     * @return error with an appropriately set message
     */
    result::Error error(std::string_view msg, const hilti::rt::filesystem::path& p = "");

    /**
     * Helper function to augment an `result::Error` with a message that
     * including driver name and, optionally, a file the error refers to.
     *
     * @param msg error message
     * @param p file to associate with the error, empty for none
     * @return error with an appropriately set message
     */
    result::Error augmentError(const result::Error& err, const hilti::rt::filesystem::path& p = "");

    /**
     * Helper function to open a file for writing.
     *
     * @param p output file
     * @param binary true to open in binary mode
     * @param append true to append to existing file
     * @return set if successful, or an appropriate error result
     */
    Result<std::ofstream> openOutput(const hilti::rt::filesystem::path& p, bool binary = false, bool append = false);

    /**
     * Helper function to open a file for reading.
     *
     * @param in input stream to open with file with
     * @param p input file
     * @return set if successful, or an appropriate error result
     */
    Result<Nothing> openInput(std::ifstream& in, const hilti::rt::filesystem::path& p);

    /**
     * Helper function to write data into an output file.
     *
     * @param in stream to read data to write from
     * @param p output file
     * @return set if successful, or an appropriate error result
     */
    Result<Nothing> writeOutput(std::ifstream& in, const hilti::rt::filesystem::path& p);

    /**
     * Helper function to read data from an input file.
     *
     * @param p input file
     * @return string stream with the file's data, or an appropriate error result
     */
    Result<std::stringstream> readInput(const hilti::rt::filesystem::path& p);

    /**
     * Copies an input stream into a temporary file on disk
     *
     * @param in stream to read from
     * @param name_hint a string to include into the temporary file's name
     * @param extension extension for the temporary file's name
     * @return the path to the temporary file, or an appropriate error result
     */
    Result<hilti::rt::filesystem::path> writeToTemp(std::ifstream& in, const std::string& name_hint,
                                                    const std::string& extension = "tmp");

    /** Save a unit's final HILTI and C++ code to disk for debugging. */
    void dumpUnit(const Unit& unit);

    /**
     * Prints an uncaught HILTI exception to stderr.
     *
     * @param e exception to print
     */
    void printHiltiException(const hilti::rt::Exception& e);

    /**
     * Hook for derived classes to add more options to the getopt() option
     * string.
     */
    virtual std::string hookAddCommandLineOptions() { return ""; }

    /** Hook for derived classes for parsing additional options. */
    virtual bool hookProcessCommandLineOption(int opt, const char* optarg) { return false; }

    /**
     * Hook for derived classes for adding content to the driver's usage
     * message (`--help`).
     */
    virtual std::string hookAugmentUsage() { return ""; }

    /**
     * Hook for derived classes to execute custom code when a new unit
     * is being added as an input file.
     */
    virtual void hookAddInput(std::shared_ptr<Unit> unit) {} // NOLINT(performance-unnecessary-value-param)

    /**
     * Hook for derived classes to execute custom code when a new source code
     * file is being added as an input file.
     */
    virtual void hookAddInput(const hilti::rt::filesystem::path& path) {}

    /**
     * Hook for derived classes to execute custom code when an HILTI AST has
     * been loaded. This hook will run before the AST has been compiled (and
     * hence it'll be fully unprocessed).
     */
    virtual void hookNewASTPreCompilation(std::shared_ptr<Unit> unit) {} // NOLINT(performance-unnecessary-value-param)

    /**
     * Hook for derived classes to execute custom code when a code unit has
     * been finalized. This hook will run after the AST has been be fully
     * processed by the suitable plugin, but before it's being transformed.
     */
    virtual void hookNewASTPostCompilation(std::shared_ptr<Unit> unit) {} // NOLINT(performance-unnecessary-value-param)

    /**
     * Hook for derived classes to execute custom code when all input files
     * have been fully processes by a plugin. If the hook returns an error that
     * will abort all further processing. The hook may add further inputs files
     * through the `add()` methods, which will then be compiled next. This
     * hook will execute again once all new inputs have likewise been compiled.
     * The new files, however, must not need processing by any plugin that has
     * already completed compilation previously.
     *
     * @param plugin plugin that has finished now
     */
    virtual Result<Nothing> hookCompilationFinished(const Plugin& plugin) { return Nothing(); }

    /**
     * Hook for derived classes to execute custom code when the HILTI runtime
     * has been initialized.
     */
    virtual void hookInitRuntime() {}

    /**
     * Hook for derived classes to execute custom code just before the HILTI
     * runtime is being shut down.
     */
    virtual void hookFinishRuntime() {}

private:
    // Tracking the state of the compilation pipeline to catch out of order
    // operation.
    enum Stage { UNINITIALIZED, INITIALIZED, COMPILED, CODEGENED, LINKED, JITTED } _stage = UNINITIALIZED;

    // Backend for adding a new unit.
    void _addUnit(const std::shared_ptr<Unit>& unit);

    // Run a specific plugini's AST passes on all units with the corresponding extension.
    Result<Nothing> _resolveUnitsWithPlugin(const Plugin& plugin, std::vector<std::shared_ptr<Unit>> units, int& round);

    // Runs a specific plugin's transform step on a given set of units.
    Result<Nothing> _transformUnitsWithPlugin(const Plugin& plugin, const std::vector<std::shared_ptr<Unit>>& units);

    // Run all plugins on current units, iterating until finished.
    Result<Nothing> _resolveUnits();

    // Turns all HILTI units into C++.
    Result<Nothing> _codegenUnits();

    // Performs global transformations on the generated code.
    Result<Nothing> _optimizeUnits();

    // Sends a debug dump of a unit's AST to the global logger.
    void _dumpAST(const std::shared_ptr<Unit>& unit, const logging::DebugStream& stream, const Plugin& plugin,
                  const std::string& prefix, int round);

    // Sends a debug dump of a unit's AST to the global logger.
    void _dumpAST(const std::shared_ptr<Unit>& unit, const logging::DebugStream& stream, const std::string& prefix);

    // Sends a debug dump of a unit's AST to an output stream.
    void _dumpAST(const std::shared_ptr<Unit>& unit, std::ostream& stream, const Plugin& plugin,
                  const std::string& prefix, int round);

    // Records a reduced debug dump of a unit's AST limited to just declarations.
    void _dumpDeclarations(const std::shared_ptr<Unit>& unit, const Plugin& plugin);

    // Records a debug dump of a unit's AST to disk.
    void _saveIterationAST(const std::shared_ptr<Unit>& unit, const Plugin& plugin, const std::string& prefix,
                           int round);

    // Records a debug dump of a unit's AST to disk.
    void _saveIterationAST(const std::shared_ptr<Unit>& unit, const Plugin& plugin, const std::string& prefix,
                           const std::string& tag);

    /**
     * Look up a symbol in the global namespace.
     *
     * @param symbol the symbol to look up
     * @return either a valid, not-nil pointer to the symbol or an error
     */
    static Result<void*> _symbol(const std::string& symbol);

    std::string _name;
    driver::Options _driver_options;
    hilti::Options _compiler_options;

    std::vector<std::shared_ptr<Unit>> _pending_units;
    std::set<ID> _processed_units;
    std::set<hilti::rt::filesystem::path> _processed_paths;

    std::shared_ptr<Context> _ctx;                      // driver's compiler context
    std::unique_ptr<hilti::JIT> _jit;                   // driver's JIT instance
    std::shared_ptr<const hilti::rt::Library> _library; // Compiled code

    std::vector<CxxCode> _generated_cxxs;
    std::unordered_map<std::string, Library> _libraries;
    std::vector<hilti::rt::filesystem::path> _external_cxxs;
    std::vector<linker::MetaData> _mds;
    std::vector<std::shared_ptr<Unit>> _hlts;

    bool _runtime_initialized = false; // true once initRuntime() has succeeded
    std::set<std::string> _tmp_files;  // all tmp files created, so that we can clean them up.
};

} // namespace hilti
