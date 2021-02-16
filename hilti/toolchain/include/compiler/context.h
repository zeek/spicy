// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/rt/any.h>
#include <hilti/rt/filesystem.h>

#include <hilti/ast/id.h>
#include <hilti/autogen/config.h>
#include <hilti/base/result.h>
#include <hilti/base/util.h>

namespace hilti {

class PluginRegistry;

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
    bool skip_validation = false; /**< if true, skip AST validation; for debugging only, things will may downhiull
                                     quickly if an AST is not well-formed  */
    bool optimize = false;        /**< generated optimized code */
    std::vector<hilti::rt::filesystem::path> library_paths; /**< additional directories to search for imported files */
    std::string cxx_namespace_extern =
        "hlt"; /**< CXX namespace for generated C++ code accessible to the host application */
    std::string cxx_namespace_intern = "__hlt"; /**< CXX namespace for generated internal C++ code */
    std::vector<hilti::rt::filesystem::path>
        cxx_include_paths; /**< additional C++ directories to search for #include files. */

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

private:
    std::map<std::string, hilti::rt::any> _aux_options;
};

namespace context {

/**
 * Index into the context's cache of already proceesed modules. Note that we
 * use ID and path interchangeably, a module can be accessed by *either*,
 * meaning that the mapping from path to ID must be consisten throughout all
 * processing.
 */
struct ModuleIndex {
    ID id;                            /**< module ID */
    hilti::rt::filesystem::path path; /**< path to module's source code on disk; can be left empty if no file exists */

    ModuleIndex() = default;
    ModuleIndex(ID id, const hilti::rt::filesystem::path& path) : id(std::move(id)), path(util::normalizePath(path)) {}
    bool operator<(const ModuleIndex& other) const { return id < other.id; }
};

/**
 * Caches information about an already processed module. Note that these are
 * "living" objects that keep being updated during AST processing. Only once
 * "final" is set, the information is assumed to correct and no longer
 * changing.
 */
struct CachedModule {
    ModuleIndex index; /**< ID and path of module */
    NodeRef node;      /**< module's root AST node */
    bool requires_compilation =
        false; /**< true if the module contains code that requires compilation itself (vs. modules that only declare
                  elements, but don't generate produce any code for linking) */
    std::optional<std::set<ModuleIndex>> dependencies; /**< further modules imported by the processed one */

    bool final = false; /**< once true, one can start relying on the other fields outside of AST processing */

    CachedModule() = default;
    CachedModule(ModuleIndex index, NodeRef node) : index(std::move(index)), node(std::move(node)) {}
};

} // namespace context

/** Context storing compiler-wide state */
class Context {
public:
    /**
     * @param options options to use for code compilation
     */
    explicit Context(Options options);

    /** Returns the context's compiler options. */
    const Options& options() const { return _options; }

    /**
     * Makes a new module known to the context, which will take ownershiup
     * and cache it, along with further meta data. A module with the same ID
     * or path must only be registered once, the method will abort otherwise.
     *
     * @param idx cache index for module
     * @param module module to cache
     * @param requires_compilation initial value for the corresponding `CachedModule` field; this may later be
     * overridden if AST processing finds out more
     * @return the meta data associated with the newly registered module
     */
    const context::CachedModule& registerModule(const context::ModuleIndex& idx, Node&& module,
                                                bool requires_compilation);

    /**
     * Updates the meta data associated with a previoysly cached module AST.
     *
     * @param module module to cache; all the fields of the struct must have been filled out
     */
    void updateModule(const context::CachedModule& module);

    /**
     * Looks up a previously cached module AST.
     *
     * @param id ID that was used to cache the AST
     * @return the meta data associated with the previously cached module, or not set if no module is associated with
     * that ID
     */
    std::optional<context::CachedModule> lookupModule(const ID& id);

    /**
     * Looks up a previously cached module AST.
     *
     * @param path path that was used to cache the AST
     * @return the meta data associated with the previously cached module, or not set if no module is associated with
     * that path
     */
    std::optional<context::CachedModule> lookupModule(const hilti::rt::filesystem::path& path);

    /**
     * Returns all (direct) dependencies that a module imports. This
     * information may be correct yet, if `final` isn't set in the module
     * meta data.
     *
     * @param meta data for all dependencies
     */
    std::vector<context::CachedModule> lookupDependenciesForModule(const ID& id);

private:
    Options _options;

    std::vector<std::pair<std::unique_ptr<Node>, std::shared_ptr<context::CachedModule>>> _modules;
    std::unordered_map<ID, std::shared_ptr<context::CachedModule>> _module_cache_by_id;
    std::unordered_map<std::string, std::shared_ptr<context::CachedModule>> _module_cache_by_path;
};

} // namespace hilti
