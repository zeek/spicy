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
#include <hilti/rt/json-fwd.h>
#include <hilti/rt/types/reference.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/module.h>
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

using MetaData = hilti::rt::ValueReference<nlohmann::json>;

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

extern void to_json(nlohmann::json& j, const Join& x);   // NOLINT
extern void from_json(const nlohmann::json& j, Join& x); // NOLINT

} // namespace linker

/** One C++ code unit. */
class Unit {
public:
    Unit(const std::shared_ptr<Context>& context);

    void setModule(const hilti::Module& m, const hilti::Unit& hilti_unit);
    cxx::ID moduleID() const { return _module_id; }

    void setUsesGlobals() { _uses_globals = true; }

    void add(const declaration::IncludeFile& i, const Meta& m = Meta());
    void add(const declaration::Global& g, const Meta& m = Meta());
    void add(const declaration::Constant& c, const Meta& m = Meta());
    void add(const declaration::Type& t, const Meta& m = Meta());
    void add(const declaration::Function& f, const Meta& m = Meta());
    void add(const Function& f, const Meta& m = Meta());
    void add(const std::string& stmt, const Meta& m = Meta()); // add generic top-level item
    void add(const linker::Join& f);

    // Prioritize type with given ID to be written out so that others
    // depending on it will have it available.
    void prioritizeType(const cxx::ID& id) {
        if ( std::find(_types_in_order.begin(), _types_in_order.end(), id) == _types_in_order.end() )
            _types_in_order.push_back(id);
    }

    bool hasDeclarationFor(const cxx::ID& id);
    std::optional<cxx::declaration::Type> lookupType(const cxx::ID& id) const;

    void addComment(const std::string& comment);
    void addInitialization(cxx::Block block) { _init_module.appendFromBlock(std::move(block)); }
    void addPreInitialization(cxx::Block block) { _preinit_module.appendFromBlock(std::move(block)); }

    Result<Nothing> finalize();

    Result<Nothing> print(std::ostream& out) const;      // only after finalize
    Result<Nothing> createPrototypes(std::ostream& out); // only after finalize
    void importDeclarations(const Unit& other);          // only after finalize
    Result<linker::MetaData> linkerMetaData() const;     // only after finalize
    cxx::ID cxxNamespace() const;

    std::shared_ptr<Context> context() const { return _context.lock(); }

    static std::pair<bool, std::optional<linker::MetaData>> readLinkerMetaData(std::istream& input);

protected:
    friend class Linker;
    Unit(const std::shared_ptr<Context>& context, cxx::ID module_id);
    Unit(const std::shared_ptr<Context>& context, cxx::ID module_id, const std::string& cxx_code);

private:
    void _generateCode(Formatter& f, bool prototypes_only);
    void _addHeader(Formatter& f);
    void _addModuleInitFunction();

    std::weak_ptr<Context> _context;

    cxx::ID _module_id;
    hilti::rt::filesystem::path _module_path;
    bool _no_linker_meta_data = false;
    bool _uses_globals = false;

    std::optional<std::string> _cxx_code;

    std::vector<std::string> _comments;
    std::set<declaration::IncludeFile> _includes;
    std::map<ID, declaration::Type> _types;
    std::vector<ID> _types_in_order;
    std::map<ID, declaration::Type> _types_forward;
    std::map<ID, declaration::Global> _globals;
    std::map<ID, declaration::Constant> _constants;
    std::map<ID, declaration::Constant> _constants_forward;
    std::multimap<ID, declaration::Function> _function_declarations;
    std::multimap<ID, Function> _function_implementations;
    std::vector<std::string> _statements;
    std::set<linker::Join> _linker_joins; // set to keep sorted.
    std::set<std::string> _namespaces;    // set to keep sorted.
    std::set<ID> _ids;

    cxx::Block _init_module;
    cxx::Block _preinit_module;
    cxx::Block _init_globals;
};

} // namespace hilti::detail::cxx
