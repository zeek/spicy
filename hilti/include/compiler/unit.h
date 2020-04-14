// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <memory>
#include <set>
#include <utility>

#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/util.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/cxx/unit.h>
#include <hilti/compiler/jit.h>

namespace hilti {
namespace linker {
/**
 * Linker meta data associated with a HILTI unit. When HILTI compiles a
 * module, it records information the HILTI's internal linker, including for
 * example any global variables the moduel defines as well what
 * initialization code it needs. The HILTI linker then later combines the
 * meta data from all HILTI modules and generated additional C++ code from it
 * for use by the HILTI runtime library.
 */
using MetaData = detail::cxx::linker::MetaData;
} // namespace linker

/**
 * Container for a single HILTI code module. For each HULTI source file, one
 * compiler unit gets instantiated. That unit then drives the process to
 * compile module comp into C++ code. While that's in progress, the unit
 * maintains state about the process, such as a cache of all external modules
 * imported by the one that's being compiled.
 */
class Unit {
public:
    /** Returns the root node of the module AST's. */
    NodeRef module() {
        assert(_id);
        return NodeRef(imported(_id));
    }

    /**
     * Returns the ID of the unit's top-level module (i.e., the one being
     * compiled).
     */
    auto id() const { return _id; }

    /**
     * Returns the path associated with the unit's top-level module (i.e.,
     * the one being compiled).
     */
    auto path() const { return _path; }

    /**
     * Compiles the unit's module AST into its final internal representation.
     * @return set if succesful, or an appropiate error result
     */
    Result<Nothing> compile();

    /** Triggers generation of C++ code from the compiled AST. */
    Result<Nothing> codegen();

    /**
     *
     * Prints out a cimpled HILTI module by recreasting its code from the
     * internal AST. Must be called only after `compile()` was succesful.
     *
     * @param out stream to print the code to
     * @return set if succesful, or an appropiate error result
     */
    Result<Nothing> print(std::ostream& out) const;

    /**
     * Prints out C++ prototypes that host applications can use to interface
     * with the generated C++ code. Must be called only after `compile()` was
     * succesful.
     *
     * @param out stream to print the code to
     * @return set if succesful, or an appropiate error result
     */
    Result<Nothing> createPrototypes(std::ostream& out);

    /**
     * Returns the generated C++ code. Must be called only after `compile()`
     * was succesful.
     *
     * @return code wrapped into the JIT's container class
     */
    Result<CxxCode> cxxCode() const;

    /**
     * Makes an external HILTI module available to the one this unit is
     * compiling. Essentially, this implements the HITLI's `import`
     * statement. Importing another module means that the compiled module
     * will know how to access the other one's functinality. However, that
     * external module will still need to be compiled itself as well; and
     * then all the compiled modules need to be linked together.
     *
     * This version of the `import` method imports by module ID: it searches
     * `Configuration::hilti_library_paths` for a file with a corresponding
     * name and extension.
     *
     * @param id ID of module to import
     * @param ext file name extension to search; `.hlt` is HILTI's standard extension, but plugins can add support for
     * other extensions as well
     * @param scope if given, qualifies the ID with a path prefix to find the
     * module (e.g., a scope of `a.b.c` will search the module in `<search path>/a/b/c/<name>`.)
     * @param  dirs additional directories to search first
     * @return the modules' cache index if successfull,or an appropiate error result if not
     */
    Result<context::ModuleIndex> import(const ID& id, const std::filesystem::path& ext, std::optional<ID> scope = {},
                                        std::vector<std::filesystem::path> search_dirs = {});

    /**
     * Makes an external HILTI module available to the one this unit is
     * compiling. See `import(const ID, const std::filesystem::path)` for
     * more details on importng.
     *
     * This version of the `import` method imports directly from a given
     * file.
     *
     * @param path to the file to import
     * @return the modules' cache index if successfull,or an appropiate error result if not
     */
    Result<context::ModuleIndex> import(const std::filesystem::path& path);

    /**
     * Returns the AST for an imported module.
     *
     * @param id module ID
     * @return Reference to the root node of the imported module's AST
     * @exception `std::out_of_range` if no module of that name has been imported yet
     */
    Node& imported(const ID& id) const;

    /**
     * Returns set of all imported modules so far.
     *
     * @param code_only if true include only dependencies that require independent compilation themselves
     */
    std::set<context::ModuleIndex> allImported(bool code_only = false) const;

    /**
     * Returns true if an imported module provides code that needs
     * independent compilation to resolve references at link-time.
     *
     * @return a boolean that true if the module provides code for
     * compilation, or an error value if no such module is known.
     */
    Result<bool> requiresCompilation(const ID& id) {
        if ( auto x = _lookupModule(id) )
            return x->requires_compilation;

        return result::Error("unknown module");
    }

    /**
     * Returns the unit's meta data for the internal HILTI linkger.
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
    bool isCompiledHILTI() const { return _have_hilti_ast; }

    /** Returns the compiler context in use. */
    std::shared_ptr<Context> context() const { return _context; }

    /** Returns the compiler options in use. */
    const Options& options() const { return _context->options(); }

    /**
     * Factory method that instantiastes a unit from an existing HILTI module
     * that's be compiled.
     *
     * This method also caches the module with the global context. Note that
     * the module's ID or path must not exist with the context yet.
     *
     * @param context glocal compiler context
     * @param module HILTI module to compile, of which the unit will take ownership
     * @param path path associated with the module, if any
     * @return instantiated unit, or an appropiate error result if operation failed
     */
    static Result<Unit> fromModule(const std::shared_ptr<Context>& context, hilti::Module&& module,
                                   const std::filesystem::path& path = "");

    /**
     * Factory method that instantiastes a unit from an existing source file that it will parse.
     *
     * This method also caches the module with the global context. Note that
     * the module's ID or path must not exist with the context yet.
     *
     * @param context glocal compiler context
     * @param path path to parse the module from
     * @return instantiated unit, or an appropiate error result if operation failed
     */
    static Result<Unit> fromSource(const std::shared_ptr<Context>& context, const std::filesystem::path& path);

    /**
     * Factory method that instantiates a unit from an existing HILTI module
     * alreached cached by the global context.
     *
     * @param context glocal compiler context
     * @param id ID of the cached module
     * @return instantiated unit, or an appropiate error result if operation failed
     */
    static Result<Unit> fromCache(const std::shared_ptr<Context>& context, const hilti::ID& id);

    /**
     * Factory method that instantiates a unit from an existing HILTI module
     * alreached cached by the global context.
     *
     * @param context glocal compiler context
     * @param path path of the cached module
     * @return instantiated unit, or an appropiate error result if operation failed
     */
    static Result<Unit> fromCache(const std::shared_ptr<Context>& context, const std::filesystem::path& path);

    /**
     * Factory method that instantiates a unit from existing C++ source code that's to compiled.
     *
     * @param context glocal compiler context
     * @param path path associated with the C++ code, if any
     * @return instantiated unit, or an appropiate error result if operation failed
     */
    static Result<Unit> fromCXX(std::shared_ptr<Context> context, detail::cxx::Unit cxx,
                                const std::filesystem::path& path = "");

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
    static Result<Unit> link(const std::shared_ptr<Context>& context, const std::vector<linker::MetaData>& mds);

    /**
     * Reads linker meta from a file. This expects the file to contain linker
     * meta somewhere inside a appropiately marked block bracked by by
     * C-style comments. When printing the generated C++ code for a compiled
     * HILTI module, it will include that block. In other words, you can just
     * save the C++ and reread the meta data with this method.
     *
     * @param input stream to read from
     * @param path file associated with the stream, for logging and error reporting
     *
     * @return If the input had valid meta data, the 1st element is true and
     * the second contains it. If the inout was valid but had no meta data
     * included, the 1st element is true whiule the 2nd remains unset. If
     * there was an error reading the input, the 1st element is false and the
     * 2nd undefined.
     */
    static std::pair<bool, std::optional<linker::MetaData>> readLinkerMetaData(
        std::istream& input, const std::filesystem::path& path = "<input stream>");

private:
    // Private constructor initializing the unit's meta data. Note that the
    // corresponding module must then be imported into the unit as well.
    // Nornmally you'd use the static ``Unit::from*()`` functions to do that
    // while creating a unit.
    Unit(std::shared_ptr<Context> context, ID id, std::filesystem::path path, bool have_hilti_ast)
        : _context(std::move(context)), _id(std::move(id)), _path(std::move(path)), _have_hilti_ast(have_hilti_ast) {}

    // Returns a list of all currently known/imported modules.
    std::vector<std::pair<ID, NodeRef>> _currentModules() const;

    // Looks up a module by its ID. The module must have been imported into
    // the unit to succeed. Assuming so, it returns the context's cache entry
    // for the module.
    std::optional<context::CachedModule> _lookupModule(const ID& id) const;

    // Backend for the public import() methods.
    Result<context::ModuleIndex> _import(const std::filesystem::path& path, std::optional<ID> expected_name);
    // Runs the validation pass and reports errors.
    bool _validateASTs(std::vector<std::pair<ID, NodeRef>>& modules,
                       std::function<bool(const ID&, NodeRef&)> run_hooks_callback);
    // Runs the validation pass and reports errors.
    bool _validateAST(const ID& id, NodeRef module, std::function<bool(const ID&, NodeRef&)> run_hooks_callback);
    // Runs the validation pass on a set of nodes and reports errors.
    bool _validateASTs(const ID& id, std::vector<Node>& nodes, std::function<bool(const ID&, std::vector<Node>&)> run_hooks_callback);
    // Updates the requires_compilation flags for all of a module's imports.
    void _determineCompilationRequirements(const Node& module);
    // Sends a debug dump of a module's AST to the global logger.
    void _dumpAST(const Node& module, const logging::DebugStream& stream, const std::string& prefix, int round = 0);
    // Sends a debug dump of all modules parsed so far to the global logger.
    void _dumpASTs(const logging::DebugStream& stream, const std::string& prefix, int round = 0);
    // Sends a debug dump of a module's AST to an output stream.
    void _dumpAST(const Node& module, std::ostream& stream, const std::string& prefix, int round = 0);
    // Sends a debug dump of all modules parsed so far to an output stream.
    void _dumpASTs(std::ostream& stream, const std::string& prefix, int round = 0);
    // Records a debug dump of all modules parsed so far to disk.
    void _saveIterationASTs(const std::string& prefix, int round = 0);

    // Parses a source file with the appropiate plugin.
    static Result<hilti::Module> parse(const std::shared_ptr<Context>& context, const std::filesystem::path& path);

    std::shared_ptr<Context> _context; // global context
    ID _id;                            // ID of top-level module being compiled by this unit
    std::filesystem::path _path;       // path of top-level module being compiled by this unit
    bool _have_hilti_ast;  // true if the top-level module comes with a HILTI AST (normally the case, but not for the
                           // linker's C++ code)
    std::set<ID> _modules; // set of all module ASTs this unit has parsed and processed (inc. imported ones)
    std::optional<detail::cxx::Unit> _cxx_unit; // compiled C++ code for this unit, once available
};

} // namespace hilti
