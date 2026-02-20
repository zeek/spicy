// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/rt/any.h>
#include <hilti/rt/filesystem.h>

#include <hilti/ast/id.h>
#include <hilti/autogen/config.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/util.h>

namespace hilti {

class PluginRegistry;
class Unit;

/**
 * Options controlling the compiler's code generation.
 *
 * In addition to HILTI's built-in options, external components can store
 * further options through auxiliary value/key mappings.
 */
struct Options {
    bool debug = false; /**< if true, generate non-optimized debug code */
    bool debug_trace =
        false; /**< if true, generate code to log statements to debug stream "hilti-trace" (requires *debug*, too) */
    bool debug_flow = false; /**< if true, generate code to log function calls and returns to debug stream "hilti-flow"
                                (requires *debug*, too) */
    bool track_location = true;   /**< if true, generate code to record current source code location during execution */
    bool skip_validation = false; /**< if true, skip AST validation; for debugging only, things may go downhill
                                     quickly if an AST is not well-formed  */
    bool enable_profiling = false; /**< if true, generate code to profile execution times of individual code sections */
    std::vector<hilti::rt::filesystem::path> library_paths; /**< additional directories to search for imported files */
    std::string cxx_namespace_extern =
        "hlt"; /**< CXX namespace for generated C++ code accessible to the host application */
    // NOTE: This should be consistent with identifiers generated with `HILTI_INTERNAL_GLOBAL_ID`.
    std::string cxx_namespace_intern = HILTI_INTERNAL_NS_ID; /**< CXX namespace for generated internal C++ code */
    std::vector<hilti::rt::filesystem::path>
        cxx_include_paths;             /**< additional C++ directories to search for #include files */
    bool keep_tmps = false;            /**< if true, do not remove generated files on exit */
    std::vector<std::string> cxx_link; /**< additional static archives or shared libraries to link during JIT */
    bool cxx_enable_dynamic_globals =
        false; /**< if true, allocate globals dynamically at runtime for (future) thread safety */
    bool global_optimizations = true;    /**< whether to run global HILTI optimizations on the generated code. */
    bool import_standard_modules = true; /**< automatically import standard modules into the global namespace. this is
                                           required, turn off only for debugging. */

    /** Option choices controlling whether to skip optimizations that change the public C++ API of generated code. */
    enum class PublicAPIMode {
        Strict, /**< skip optimizations that change the public C++ API of generated code.  [default in debug builds] */
        NonStrict, /**< allow optimizations that change the public C++ API of generated code. [default in release
                      builds] */
        Default,   /**< will be replaced automatically before AST processing starts with either strict/non-strict, based
                      on build mode */
    };

    PublicAPIMode public_api_mode = PublicAPIMode::Default;

    /**
     * Retrieves the value for an auxiliary option.
     *
     * @param key unique key, which should use a namespaced `x.y` structure.
     * @param default value to return if key has not been explicitly set
     * @tparam type of the key's value, which must match the type used when
     * the option is being set
     *
     * @return either the recorded value for *key*, or *default* none
     */
    template<typename T>
    T getAuxOption(const std::string& key, T default_) const {
        auto i = _aux_options.find(key);
        if ( i != _aux_options.end() )
            return hilti::rt::any_cast<T>(i->second);
        else
            return default_;
    }

    /**
     * Sets the value for an auxiliary option.
     *
     * @param key unique key, which should use a namespaced `x.y` structure.
     * @param value value to record for the option
     * @tparam type of the key's value, which must match the type used when
     * the option is being retrieved
     */
    template<typename T>
    void setAuxOption(const std::string& key, T value) {
        _aux_options[key] = value;
    }

    /**
     * Parses a comma-separated list of tokens indicating which additional
     * debug instrumentation to activate, and sets the instance's
     * corresponding options.
     *
     * @return An error if a flag isn't known.
     */
    Result<Nothing> parseDebugAddl(const std::string& flags);

    /** Prints out a humand-readable version of the current options. */
    void print(std::ostream& out) const;

private:
    std::map<std::string, hilti::rt::any> _aux_options;
};

namespace context {} // namespace context

/** Context storing compiler-wide state */
class Context {
public:
    /**
     * @param options options to use for code compilation
     */
    explicit Context(Options options);

    /** Destructor. */
    ~Context();

    /** Returns the context's compiler options. */
    const Options& options() const { return _options; }

    /** Returns the global AST context. */
    auto* astContext() const { return _ast_context.get(); }

private:
    Options _options;
    std::unique_ptr<ASTContext> _ast_context;
};

} // namespace hilti
