// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/node.h>
#include <hilti/base/uniquer.h>
#include <hilti/compiler/unit.h>

#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>

namespace spicy::detail {

/**
 * Spicy's code generator. This is the main internal entry point for
 * generating HILTI code from Spicy source code. The Spicy AST reuses many
 * HILTI nodes. The code generator's task is to convert a mixed Spicy/HILTI
 * AST into a pure HILTI AST.
 */
class CodeGen {
public:
    CodeGen(const std::shared_ptr<hilti::Context>& context) : _context(context), _gb(this), _pb(this) {}

    /** Entry point for transformation from a Spicy AST to a HILTI AST. */
    bool compileModule(hilti::Node* root, hilti::Unit* u);

    auto context() const { return _context.lock(); }
    const auto& options() const { return context()->options(); }

    hilti::Type compileUnit(const type::Unit& unit,
                            bool declare_only = true); // Compiles a Unit type into its HILTI struct representation.

    std::optional<hilti::declaration::Function> compileHook(
        const type::Unit& unit, const ID& id,
        std::optional<std::reference_wrapper<const type::unit::item::Field>> field, bool foreach, bool debug,
        std::vector<type::function::Parameter> params, std::optional<hilti::Statement> body,
        std::optional<Expression> /*priority*/, const hilti::Meta& meta);

    // These must be called only while a module is being compiled.
    codegen::ParserBuilder* parserBuilder() { return &_pb; }
    codegen::GrammarBuilder* grammarBuilder() { return &_gb; }
    hilti::Unit* hiltiUnit() const;     // will abort if not compiling a module.
    hilti::Module* hiltiModule() const; // will abort if not compiling a module.
    auto uniquer() { return &_uniquer; }

    const auto& moduleProperties() const { return _properties; }
    void recordModuleProperty(hilti::declaration::Property p) { _properties.emplace_back(std::move(p)); }

    void addDeclaration(Declaration d) {
        _decls_added.insert(d.id());
        _new_decls.push_back(std::move(d));
    }

    bool haveAddedDeclaration(const ID& id) { return _decls_added.find(id) != _decls_added.end(); }


private:
    std::weak_ptr<hilti::Context> _context;
    codegen::GrammarBuilder _gb;
    codegen::ParserBuilder _pb;

    std::vector<hilti::declaration::Property> _properties;

    hilti::Unit* _hilti_unit = nullptr;
    hilti::Node* _root = nullptr;
    std::vector<Declaration> _new_decls;
    std::unordered_set<ID> _decls_added;
    hilti::util::Uniquer<std::string> _uniquer;
};

} // namespace spicy::detail
