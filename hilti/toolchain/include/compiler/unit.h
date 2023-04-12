// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <unistd.h>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/util.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/cxx/unit.h>
#include <hilti/compiler/jit.h>

namespace hilti {

struct Plugin;

namespace linker {
/**
 * Linker meta data associated with a HILTI unit. When HILTI compiles a
 * module, it records information the HILTI's internal linker, including for
 * example any global variables the module defines as well what
 * initialization code it needs. The HILTI linker then later combines the
 * meta data from all HILTI modules and generated additional C++ code from it
 * for use by the HILTI runtime library.
 */
using MetaData = detail::cxx::linker::MetaData;
} // namespace linker

/**
 * Container for a single HILTI code module. For each HILTI source file, one
 * compiler unit gets instantiated. That unit then drives the process to
 * compile the module AST into C++ code. While that's in progress, the unit
 * maintains state about the process, such as a list of dependencies this unit
 * requires.
 */
class Unit {
public:
    /** Destructor. */
    ~Unit();

    /** Returns a reference to the root node of the module AST's. */
    NodeRef moduleRef() const { return _module ? NodeRef(*_module) : NodeRef(); }

    /**
     * Returns the root node of the module AST's. Must only be called if
     * `isCompiledHilti()` returns true.
     */
    Node& module() {
        assert(_module);
        return *_module;
    }

    /**
     * Returns the index to use when storing the unit inside the context's
     * unit cache.
     */
    const auto& cacheIndex() const { return _index; }

    /** Returns the ID of the unit's module. */
    const auto& id() const { return _index.id; }

    /**
     * Returns an ID for the unit's module that's globally unique across all
     * units processed within the current context. This ID will often be the
     * same as returned by `id()`, but it may include an additional string for
     * unification, in particular if there are more than one module with the
     * same ID.
     *
     * @returns globally unique ID for the module; the method guaranteees that
     * the ID represents a valid C++ identifier
     */
    ID uniqueID() const { return _unique_id; }

    /** Returns the path associated with the unit's module. */
    const auto& path() const { return _index.path; }

    /**
     * Returns the file extension associated with the unit's code. This
     * extension determines which plugin the unit's AST will be processed with.
     * Note that this does not necessarily match the extension of module's
     * source path.
     */
    const auto& extension() const { return _extension; }

    /**
     * Set a file extension associagted with the unit's code. By default, the
     * extension is set when a AST module is being created, for example from
     * the file it's being parsed from. This method can explicitly override the
     * extension to have the AST processed by a different plugin.
     *
     * @param ext new extension
     */
    void setExtension(const hilti::rt::filesystem::path& ext) { _extension = ext; }

    enum ASTState { Modified, NotModified };

    /** Clears any scopes and errors accumulated inside the unit's AST. */
    void resetAST();

    /**
     * Runs a plugin's scope-building phase on the unit's AST.
     *
     * @param plugin plugin to execute
     * @returns success if no error occurred, and an appropriate error otherwise
     */
    Result<Nothing> buildASTScopes(const Plugin& plugin);

    /**
     * Runs a plugin's resolver phase on the unit's AST.
     *
     * @param plugin plugin to execute
     * @returns flag indicating whether the AST was modified or not; or an
     * appropriate error if a failure occurred
     */
    Result<ASTState> resolveAST(const Plugin& plugin);

    /**
     * Runs a plugin's validation phase on the unit's AST before resolving.
     *
     * @param plugin plugin to execute
     * @returns true if the AST does not contain any errors
     */
    bool validateASTPre(const Plugin& plugin);

    /**
     * Runs a plugin's validation phase on the unit's AST after resolving.
     *
     * @param plugin plugin to execute
     * @returns true if the AST does not contain any errors
     */
    bool validateASTPost(const Plugin& plugin);

    /**
     * Runs a plugin's transformation phase on the unit's AST.
     *
     * @param plugin plugin to execute
     * @returns success if no error occurred, and an appropriate error otherwise
     */
    Result<Nothing> transformAST(const Plugin& plugin);

    /**
     * Triggers generation of C++ code from the compiled AST.
     *
     * @returns success if no error occurred, and an appropriate error otherwise
     */
    Result<Nothing> codegen();

    /**
     *
     * Prints out a HILTI module by recreating its code from the
     * internal AST. Must be called only after `compile()` was successful.
     *
     * @param out stream to print the code to
     * @return set if successful, or an appropriate error result
     */
    Result<Nothing> print(std::ostream& out) const;

    /**
     * Prints out C++ prototypes that host applications can use to interface
     * with the generated C++ code. Must be called only after `compile()` was
     * successful.
     *
     * @param out stream to print the code to
     * @return set if successful, or an appropriate error result
     */
    Result<Nothing> createPrototypes(std::ostream& out);

    /**
     * Returns the generated C++ code. Must be called only after `compile()`
     * was successful.
     *
     * @return code wrapped into the JIT's container class
     */
    Result<CxxCode> cxxCode() const;

    /**
     * Returns the list of dependencies registered for the unit so far.
     *
     * @param recursive if true, return the transitive closure of all
     * dependent units, vs just direct dependencies of the current unit
     */
    std::vector<std::weak_ptr<Unit>> dependencies(bool recursive = false) const;

    /** Removes any dependencies registered for the unit so far. */
    void clearDependencies() { _dependencies.clear(); };

    /**
     * Register a dependency on another unit for the current one.
     *
     * @param unit the unit this one depends on
     * @returns true if this is a new dependency that had not been previously added
     */
    bool addDependency(const std::shared_ptr<Unit>& unit);

    /**
     * Returns the unit's meta data for the internal HILTI linker.
     *
     * @return meta data, or an error if no code has been compiled yet
     */
    Result<linker::MetaData> linkerMetaData() const {
        if ( _cxx_unit )
            return _cxx_unit->linkerMetaData();

        return result::Error("no C++ code compiled");
    }

    /**
     * Returns true if this unit has been compiled from HILTI source. This is
     * usually the case, but we also represent HILTI's linker output as a
     * unit and there's no corresponding HILTI source code for that.
     */
    bool isCompiledHILTI() const { return _module.has_value(); }

    /**
     * Returns true if the AST has been determined to contain code that needs
     * to be compiled as its own C++ module, rather than just declaration for
     * other units.
     */
    bool requiresCompilation();

    /**
     * Explicily marks the unit as requiring compilation down to C++, overriding
     * any automatic determination.
     */
    void setRequiresCompilation() { _requires_compilation = true; }

    /**
     * Returns true if the unit has been marked as fully resolved, so that no further AST processing is needed.
     */
    bool isResolved() { return _resolved; }

    /**
     * Sets the resolver state for the unit.
     *
     * @param resolved true to mark the module as fully resolved, so that no
     * further AST processing is needed
     */
    void setResolved(bool resolved) { _resolved = resolved; }

    /** Returns the compiler context in use. */
    std::shared_ptr<Context> context() const { return _context.lock(); }

    /** Returns the compiler options in use. */
    const Options& options() const { return context()->options(); }

    /**
     * Factory method that instantiates a unit from an existing source file
     * that it will parse.
     *
     * This method also caches the module with the global context. Note that
     * the module's ID or path should usually not exist with the context yet.
     *
     * @param context global compiler context
     * @param path path to parse the module from
     * @param scope import-from scope associated with the import operation, if any
     * @param ast_extension extension indicating which plugin to use for
     * processing the AST; if not given, this will be taken from the filename
     * @return instantiated unit, or an appropriate error result if operation failed
     */
    static Result<std::shared_ptr<Unit>> fromSource(const std::shared_ptr<Context>& context,
                                                    const hilti::rt::filesystem::path& path,
                                                    const std::optional<ID>& scope,
                                                    std::optional<hilti::rt::filesystem::path> process_extension = {});

    /**
     * Factory method that instantiates a unit from an existing HILTI AST.
     *
     * This method also caches the module with the global context. Note that
     * the module's ID or path should usually not exist with the context yet.
     * If it does, this one will replace the existing version.
     *
     * @param context global compiler context
     * @param module  AST of the module
     * @param extension extension indicating which plugin to use for
     * processing the AST
     * @return instantiated unit, or an appropriate error result if operation failed
     */
    static std::shared_ptr<Unit> fromModule(const std::shared_ptr<Context>& context, const hilti::Module& module,
                                            hilti::rt::filesystem::path extension);

    /**
     * Factory method that instantiates a unit for an `import` statement,
     * performing the search for the right source file first.
     *
     * This method also caches the module with the global context. Note that
     * the module's ID or path should usually not exist with the context yet.
     *
     * @param context global compiler context
     * @param id ID of the module to be imported
     * @param parse_extension file extension indicating how to parse the module's source file
     * @param ast_extension extension indicating which plugin to use for
     * processing the AST; this will usually match `parse_extension`, but
     * doesn't need to.
     * @return instantiated unit, or an appropriate error result if operation failed
     */
    static Result<std::shared_ptr<Unit>> fromImport(const std::shared_ptr<Context>& context, const ID& id,
                                                    const hilti::rt::filesystem::path& parse_extension,
                                                    const hilti::rt::filesystem::path& process_extension,
                                                    std::optional<ID> scope,
                                                    std::vector<hilti::rt::filesystem::path> search_dirs);

    /**
     * Factory method that instantiates a unit from an existing HILTI module
     * already cached by the global context.
     *
     * @param context global compiler context
     * @param path path of the cached module
     * @param scope import-from scope associated with the existing module
     * @return instantiated unit, or an appropriate error result if operation failed
     */
    static Result<std::shared_ptr<Unit>> fromCache(const std::shared_ptr<Context>& context,
                                                   const hilti::rt::filesystem::path& path,
                                                   const std::optional<ID>& scope);

    /**
     * Factory method that instantiates a unit from existing C++ source code
     * that's to compiled.
     *
     * @param context global compiler context
     * @param path path associated with the C++ code, if any
     * @return instantiated unit, or an appropriate error result if operation failed
     */
    static Result<std::shared_ptr<Unit>> fromCXX(const std::shared_ptr<Context>& context, detail::cxx::Unit cxx,
                                                 const hilti::rt::filesystem::path& path = "");

    /**
     * Entry point for the HILTI linker, The linker combines meta data from
     * several compiled HILTI modules and creates an additional unit from it,
     * with its C++ code representing logic the HILTI runtime library will
     * draw upon.
     *
     * @param context compiler context to use
     * @param mds set of meta data from modules to be linked together
     * @return a unit representing additional C++ code that the modules need to function
     */
    static Result<std::shared_ptr<Unit>> link(const std::shared_ptr<Context>& context,
                                              const std::vector<linker::MetaData>& mds);

    /**
     * Reads linker meta from a file. This expects the file to contain linker
     * meta somewhere inside a appropriately marked block bracketed by
     * C-style comments. When printing the generated C++ code for a compiled
     * HILTI module, it will include that block. In other words, you can just
     * save the C++ and reread the meta data with this method.
     *
     * @param input stream to read from
     * @param path file associated with the stream, for logging and error reporting
     *
     * @return If the input had valid meta data, the 1st element is true and
     * the second contains it. If the input was valid but had no meta data
     * included, the 1st element is true while the 2nd remains unset. If
     * there was an error reading the input, the 1st element is false and the
     * 2nd undefined.
     */
    static std::pair<bool, std::optional<linker::MetaData>> readLinkerMetaData(
        std::istream& input, const hilti::rt::filesystem::path& path = "<input stream>");

private:
    // Private constructor initializing the unit's meta data. Use the public
    // `from*()` factory functions instead to instantiate a unit.
    Unit(const std::shared_ptr<Context>& context, const ID& id, const std::optional<ID>& scope,
         const hilti::rt::filesystem::path& path, hilti::rt::filesystem::path extension, Node&& module)
        : _index(id, scope, util::normalizePath(path)),
          _unique_id(_makeUniqueID(id)),
          _extension(std::move(std::move(extension))),
          _module(std::move(module)),
          _context(context) {}

    Unit(const std::shared_ptr<Context>& context, const ID& id, const std::optional<ID>& scope,
         const hilti::rt::filesystem::path& path, hilti::rt::filesystem::path extension,
         std::optional<detail::cxx::Unit> cxx_unit = {})
        : _index(id, scope, util::normalizePath(path)),
          _unique_id(_makeUniqueID(id)),
          _extension(std::move(std::move(extension))),
          _context(context),
          _cxx_unit(std::move(cxx_unit)) {}

    // Make a given ID globally unique.
    ID _makeUniqueID(const ID& id);

    // Backend for the public import() methods.
    Result<context::CacheIndex> _import(const hilti::rt::filesystem::path& path, std::optional<ID> expected_name);

    // Reports any errors recorded in the AST to stderr.
    //
    // @returns false if there were errors, true if the AST is all good
    bool _collectErrors();

    // Recursively destroys the module's AST.
    void _destroyModule();

    // Helper for dependencies() to recurse.
    void _recursiveDependencies(std::vector<std::weak_ptr<Unit>>* dst, std::unordered_set<const Unit*>* seen) const;

    // Parses a source file with the appropriate plugin.
    static Result<hilti::Module> _parse(const std::shared_ptr<Context>& context,
                                        const hilti::rt::filesystem::path& path);

    context::CacheIndex _index;                     // index for the context's module cache
    ID _unique_id;                                  // globally unique ID for this module
    hilti::rt::filesystem::path _extension;         // AST extension, which may differ from source file
    std::optional<Node> _module;                    // root node for AST (always a `Module`), if available
    std::vector<std::weak_ptr<Unit>> _dependencies; // recorded dependencies
    std::weak_ptr<Context> _context;                // global context
    std::optional<detail::cxx::Unit> _cxx_unit;     // compiled C++ code for this unit, once available
    bool _resolved = false;                         // state of resolving the AST
    bool _requires_compilation = false;             // mark explicitly as requiring compilation to C++

    static std::unordered_map<ID, unsigned int> _uid_cache; // cache storing state for generating globally unique IDs
};

} // namespace hilti
