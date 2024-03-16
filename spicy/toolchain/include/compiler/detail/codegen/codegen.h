// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/node.h>
#include <hilti/base/uniquer.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/unit.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>

namespace spicy::detail {

namespace codegen {
class GrammarBuilder;
class ParserBuilder;
} // namespace codegen

/**
 * Spicy's code generator. This is the main internal entry point for
 * generating HILTI code from Spicy source code. The Spicy AST reuses many
 * HILTI nodes. The code generator's task is to convert a mixed Spicy/HILTI
 * AST into a pure HILTI AST.
 */
class CodeGen {
public:
    CodeGen(Builder* builder) : _builder(builder), _gb(this), _pb(this) {}

    auto builder() const { return _builder; }
    auto context() const { return builder()->context(); }
    auto driver() const { return context()->driver(); }
    const auto& compilerContext() const { return driver()->context(); }
    const auto& options() const { return compilerContext()->options(); }

    /** Entry point for transformation from a Spicy AST to a HILTI AST. */
    bool compileAST(hilti::ASTRoot* root);

    /** Turns a Spicy unit into a HILTI struct, along with all the necessary implementation code. */
    UnqualifiedType* compileUnit(
        type::Unit* unit,
        bool declare_only = true); // Compiles a Unit type into its HILTI struct representation.

    hilti::declaration::Function* compileHook(const type::Unit& unit, const ID& id, type::unit::item::Field* field,
                                              bool foreach, bool debug, hilti::type::function::Parameters params,
                                              hilti::Statement* body, Expression* priority, const hilti::Meta& meta);

    // These must be called only while a module is being compiled.
    codegen::ParserBuilder* parserBuilder() { return &_pb; }
    codegen::GrammarBuilder* grammarBuilder() { return &_gb; }
    hilti::declaration::Module* hiltiModule() const; // will abort if not compiling a module.
    auto uniquer() { return &_uniquer; }

    const auto& moduleProperties() const { return _properties; }
    void recordModuleProperty(hilti::declaration::Property p) { _properties.emplace_back(std::move(p)); }

    /**
     * Records a mapping from a Spicy type to its corresponding, compiled HILTI
     * type. This is used to track compiled types during code generation
     * without immediately performance the actual replacement of the AST node.
     * We leave the latter to a later stage, which will replace all recorded
     * mappings at the end when its safe to modify the AST.
     */
    auto recordTypeMapping(UnqualifiedType* from, UnqualifiedType* to) { _type_mappings[from] = to; }

    /**
     * Records a new declaration to be added to the current module. The
     * additional will be performed at the end of codegen when its safe to
     * modify the AST.
     */
    void addDeclaration(Declaration* d) {
        _decls_added.insert(d->id());
        _new_decls.push_back(d);
    }

    /**
     * Returns true if a declaration with the given ID has been scheduled for
     * additional via `addDeclaration()` already.
     */
    bool haveAddedDeclaration(const ID& id) { return _decls_added.find(id) != _decls_added.end(); }

private:
    bool _compileModule(hilti::declaration::Module* module, int pass);
    void _updateDeclarations(visitor::MutatingPostOrder* v, hilti::declaration::Module* module);

    Builder* _builder;
    codegen::GrammarBuilder _gb;
    codegen::ParserBuilder _pb;

    std::vector<hilti::declaration::Property> _properties;
    std::map<UnqualifiedType*, UnqualifiedType*> _type_mappings;

    hilti::declaration::Module* _hilti_module = nullptr;
    Declarations _new_decls;
    std::unordered_set<ID> _decls_added;
    hilti::util::Uniquer<std::string> _uniquer;
};

} // namespace spicy::detail
