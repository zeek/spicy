// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <unistd.h>

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <hilti/ast/declarations/module.h>
#include <hilti/ast/id.h>
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

    /**
     * Returns the root node of the module's AST. Must only be called if
     * `isCompiledHilti()` returns true.
     */
    declaration::Module* module() const;

    /** Returns the unique module ID associated with the unit. */
    const auto& uid() const { return _uid; }

    /** * Sets the unique module ID associated with the unit. **/
    void setUID(const declaration::module::UID& uid) { _uid = uid; }

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
    std::set<declaration::module::UID> dependencies(bool recursive = false) const;

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
     * Returns true if this unit has HILTI source code available. This is
     * usually the case, but we also represent HILTI's linker output as a unit
     * and there's no corresponding HILTI source code for that.
     */
    bool isCompiledHILTI() const;

    /**
     * Returns true if the AST has been determined to contain code that needs
     * to be compiled as its own C++ module, rather than just declaration for
     * other units.
     */
    bool requiresCompilation();

    /**
     * Explicitly marks the unit as requiring compilation down to C++, overriding
     * any automatic determination.
     */
    void setRequiresCompilation() { _requires_compilation = true; }

    /** Returns the compiler context in use. */
    std::shared_ptr<Context> context() const { return _context.lock(); }

    /** Returns the compiler options in use. */
    const Options& options() const { return context()->options(); }

    /**
     * Factory method that instantiates a unit from an existing source file
     * that it will parse.
     *
     * @param context global compiler context
     * @param path path to parse the module from
     * @return instantiated unit, or an appropriate error result if operation failed
     */
    static Result<std::shared_ptr<Unit>> fromSource(const std::shared_ptr<Context>& context, Builder* builder,
                                                    const hilti::rt::filesystem::path& path);

    /**
     * Factory method that instantiates a unit from existing C++ source code
     * that's to compiled.
     *
     * @param context global compiler context
     * @param path path associated with the C++ code, if any
     * @return instantiated unit, or an appropriate error result if operation failed
     */
    static Result<std::shared_ptr<Unit>> fromCXX(const std::shared_ptr<Context>& context,
                                                 std::shared_ptr<detail::cxx::Unit> cxx,
                                                 const hilti::rt::filesystem::path& path = "");

    // Must already be part of AST.
    static std::shared_ptr<Unit> fromExistingUID(const std::shared_ptr<Context>& context, declaration::module::UID uid);


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

private:
    // Private constructor initializing the unit's meta data. Use the public
    // `from*()` factory functions instead to instantiate a unit.
    Unit(const std::shared_ptr<Context>& context, declaration::module::UID uid)
        : _context(context), _uid(std::move(uid)) {}
    Unit(const std::shared_ptr<Context>& context, declaration::module::UID uid,
         std::shared_ptr<detail::cxx::Unit> cxx_unit)
        : _context(context), _uid(std::move(uid)), _cxx_unit(std::move(cxx_unit)) {}

    Result<std::shared_ptr<detail::cxx::Unit>> _codegenModule(const declaration::module::UID& uid);

    std::weak_ptr<Context> _context;              // global context
    declaration::module::UID _uid;                // module's globally unique ID
    std::shared_ptr<detail::cxx::Unit> _cxx_unit; // compiled C++ code for this unit, once available
    bool _requires_compilation = false;           // mark explicitly as requiring compilation to C++
};

} // namespace hilti
