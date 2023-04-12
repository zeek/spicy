// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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
    std::string cxx_namespace_intern = "__hlt"; /**< CXX namespace for generated internal C++ code */
    std::vector<hilti::rt::filesystem::path>
        cxx_include_paths;             /**< additional C++ directories to search for #include files */
    bool keep_tmps = false;            /**< if true, do not remove generated files on exit */
    std::vector<std::string> cxx_link; /**< additional static archives or shared libraries to link during JIT */
    bool cxx_enable_dynamic_globals =
        false; /**< if true, allocate globals dynamically at runtime for (future) thread safety */

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

namespace context {

/**
 * Index into the context's cache of already processed modules. Note that we
 * use ID and path interchangeably, a module can be accessed by *either*,
 * meaning that the mapping from path to ID must be consistent throughout all
 * processing.
 */
struct CacheIndex {
    ID id;                            /**< module ID */
    ID scope;                         /**< import scope  */
    hilti::rt::filesystem::path path; /**< path to module's source code on disk; can be left empty if no file exists */

    auto scopedID() const { return scope + id; }

    CacheIndex() = default;
    CacheIndex(ID id, const std::optional<ID>& scope, const hilti::rt::filesystem::path& path)
        : id(std::move(id)), scope(scope ? *scope : ID()), path(util::normalizePath(path)) {}
};

/**
 * Caches information about an already processed module. Note that these are
 * "living" objects that keep being updated during AST processing. Only once
 * "final" is set, the information is assumed to correct and no longer
 * changing.
 */
struct CacheEntry {
    std::shared_ptr<Unit> unit; /**< cached unit */

    CacheEntry() = default;
    CacheEntry(std::shared_ptr<Unit> unit) : unit(std::move(unit)) {}
};

} // namespace context

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

    /**
     * Caches a code unit inside the context. The cache uses a unit's `(ID,
     * path)` tuple as the index. Any previously cached unit with the same
     * index tuple will be replaced.
     *
     * @param unit unit to cache
     * @return the meta data associated with the newly registered module
     */
    void cacheUnit(const std::shared_ptr<Unit>& unit);

    /**
     * Looks up a previously cached unit by its ID.
     *
     * @param id module ID look up a unit for
     * @param scope import-from scope associated with the import operation, if any
     * @param extension a file extension expected for the unit, indicating its
     * source language; a cached unit will only be returned if its extension
     * matches
     * @return the cache entry associated with the path if found
     */
    std::optional<context::CacheEntry> lookupUnit(const ID& id, const std::optional<ID>& scope,
                                                  const hilti::rt::filesystem::path& extension);

    /**
     * Looks up a previously cached unit by its path. It will only return a
     * cached module if its extension matches that of the given path.
     *
     * @param path path to look up a unit for
     * @param scope import-from scope associated with the path being imported, if any
     * @return the cache entry associated with the path if found
     */
    std::optional<context::CacheEntry> lookupUnit(const hilti::rt::filesystem::path& path,
                                                  const std::optional<ID>& scope,
                                                  std::optional<hilti::rt::filesystem::path> ast_extension = {});

    /**
     * Looks up a previously cached unit using an existing cache index as the key.
     *
     * @param idx cache index to look up
     * @return the cache entry associated with the path if found
     */
    std::optional<context::CacheEntry> lookupUnit(const context::CacheIndex& idx,
                                                  const std::optional<hilti::rt::filesystem::path>& ast_extension = {});

    /**
     * Returns all (direct & indirect) dependencies that a module imports. This
     * information will be complete only once all AST have been fully resolved.
     *
     * @param idx cache index for the module which to return dependencies for
     * @return set of dependencies
     */
    std::vector<std::weak_ptr<Unit>> lookupDependenciesForUnit(const context::CacheIndex& idx,
                                                               const hilti::rt::filesystem::path& extension);

    /**
     * Dumps the current state of the unit cache to a debug stream.
     *
     * @param stream debug stream to write to
     */
    void dumpUnitCache(const hilti::logging::DebugStream& stream);

private:
    Options _options;

    std::unordered_map<ID, std::shared_ptr<context::CacheEntry>> _unit_cache_by_id;
    std::unordered_map<std::string, std::shared_ptr<context::CacheEntry>> _unit_cache_by_path;
};

} // namespace hilti
