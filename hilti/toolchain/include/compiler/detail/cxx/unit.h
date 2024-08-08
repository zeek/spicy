// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>
#include <hilti/rt/types/reference.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/base/result.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/cxx/elements.h>
#include <hilti/compiler/detail/cxx/formatter.h>

namespace hilti::detail::cxx {

class Linker;

namespace linker {

/**
 * Function joined by the linker.
 *
 * The HILTI linker will generate a C++ function `<id>` that calls all
 * `callee` function registered for that ID.
 */
struct Join {
    cxx::ID id;                        /**< name of externally visible function */
    cxx::declaration::Function callee; /**< callee function to execute through linker function */
    std::list<cxx::declaration::Type>
        aux_types; /**< additional types the linker needs to declare for external prototype to work */
    int64_t priority =
        0; /**< Priority determining the order between callees; higher priority callees will be called first */
    bool declare_only = false; /**< only declare the joined C++ function, don't generate the implementation */

    bool operator<(const Join& other) const {
        return std::make_tuple(id, priority, callee.id) < std::make_tuple(other.id, other.priority, other.callee.id);
    }
};

struct MetaData {
    ID module;
    ID namespace_;
    hilti::rt::filesystem::path path;
    std::set<Join> joins;
    cxx::declaration::Constant globals_index;
};

} // namespace linker

/** One C++ code unit. */
class Unit {
public:
    Unit(const std::shared_ptr<Context>& context, hilti::declaration::Module* module);

    auto* module() const {
        assert(_module); // available only if module was passed to constructor
        return _module;
    };

    const auto& cxxModuleID() const { return _module_id; }
    cxx::ID cxxInternalNamespace() const;
    cxx::ID cxxExternalNamespace() const;

    void setUsesGlobals() { _uses_globals = true; }

    template<typename Declaration,
             typename std::enable_if_t<std::is_base_of_v<declaration::DeclarationBase, Declaration>>* = nullptr>
    void add(const Declaration& d, const Meta& m = Meta());  // add C++ declaration
    void add(std::string_view stmt, const Meta& m = Meta()); // add generic top-level item
    void add(const linker::Join& f);                         // add linker joined function

    void addComment(std::string_view comment);
    void addInitialization(cxx::Block block) { _init_module.appendFromBlock(std::move(block)); }
    void addPreInitialization(cxx::Block block) { _preinit_module.appendFromBlock(std::move(block)); }

    // @param include_all_implementations if true, do not filter out function
    // implementations that aren't within the module's own namespace.
    Result<Nothing> finalize(bool include_all_implementations = false);

    Result<Nothing> print(std::ostream& out) const;      // only after finalize
    Result<Nothing> createPrototypes(std::ostream& out); // only after finalize
    Result<linker::MetaData> linkerMetaData() const;     // only after finalize

    std::shared_ptr<Context> context() const { return _context.lock(); }

protected:
    friend class Linker;
    Unit(const std::shared_ptr<Context>& context, cxx::ID module_id, const std::string& cxx_code = {});

private:
    enum class Phase { Includes, Forwards, Enums, Types, Constants, Globals, Functions, TypeInfos, Implementations };
    using cxxDeclaration = std::variant<declaration::IncludeFile, declaration::Global, declaration::Constant,
                                        declaration::Type, declaration::Function>;

    void _generateCode(Formatter& f, bool prototypes_only, bool include_all_implementations);
    void _emitDeclarations(const cxxDeclaration& decl, Formatter& f, Phase phase, bool prototypes_only,
                           bool include_all_implementations);
    void _addHeader(Formatter& f);
    void _addModuleInitFunction();

    std::weak_ptr<Context> _context;

    hilti::declaration::Module* _module = nullptr;
    cxx::ID _module_id;
    hilti::rt::filesystem::path _module_path;
    bool _no_linker_meta_data = false;
    bool _uses_globals = false;

    std::optional<std::string> _cxx_code;

    std::vector<std::pair<ID, cxxDeclaration>> _declarations; // maintains order of insertion
    std::multimap<ID, cxxDeclaration> _declarations_by_id;    // index into declarations by their ID

    std::vector<std::string> _comments;
    std::vector<std::string> _statements;
    std::set<linker::Join> _linker_joins; // set to keep sorted.
    cxx::Block _init_module;
    cxx::Block _preinit_module;
    cxx::Block _init_globals;
};

template<typename Declaration, typename std::enable_if_t<std::is_base_of_v<declaration::DeclarationBase, Declaration>>*>
void Unit::add(const Declaration& d, const Meta& m) {
    static_assert(std::is_base_of_v<declaration::DeclarationBase, Declaration>,
                  "Declaration must be derived from DeclarationBase");

    // Check if the same declaration has already been added.
    auto decls = _declarations_by_id.equal_range(d.id);
    for ( auto i = decls.first; i != decls.second; i++ ) {
        auto* other = std::get_if<Declaration>(&i->second);
        if ( ! other ) {
            logger().internalError(
                util::fmt("mismatched declaration types in cxx::Unit::add for ID %s: got a %s, but already have a %s",
                          d.id, typeid(d).name(), typeid(i->second).name()));
        }

        if ( *other == d )
            // Have it already, nothing to do.
            return;
    }

    _declarations.emplace_back(d.id, d);

    if ( d.id )
        _declarations_by_id.emplace(d.id, d);
}

} // namespace hilti::detail::cxx
