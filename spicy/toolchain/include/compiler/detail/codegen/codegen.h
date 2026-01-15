// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <set>
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

// Information collected from the AST in an initial pass for any code generation.
struct ASTInfo {
    std::set<ID> uses_sync_advance; // type ID of units implementing %sync_advance
    std::set<uint64_t> look_aheads_in_use;
    std::set<ID> units_with_references; // IDs of all unit types that are wrapped into a reference somewhere
};

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
    const auto& astInfo() const { return _ast_info; }

    /** Entry point for transformation from a Spicy AST to a HILTI AST. */
    bool compileAST(hilti::ASTRoot* root);

    /** Turns a Spicy unit into a HILTI struct, along with all the necessary implementation code. */
    UnqualifiedType* compileUnit(
        type::Unit* unit,
        bool declare_only = true); // Compiles a Unit type into its HILTI struct representation.

    /** For a public unit type alias, creates the runtime code to register the parser under the alias name. */
    void compilePublicUnitAlias(hilti::declaration::Module* module, const ID& alias_id, type::Unit* unit);

    hilti::declaration::Function* compileHook(const type::Unit& unit, const ID& id, type::unit::item::Field* field,
                                              declaration::hook::Type type, bool debug,
                                              hilti::type::function::Parameters params, hilti::statement::Block* body,
                                              Expression* priority, const hilti::Meta& meta);

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
    void addDeclaration(Declaration* d) { _new_decls.push_back(d); }

    /**
     * Adds a global constant to the current module and returns an expression
     * referring to it. If this is called multiple times for the same value,
     * only one instance is created and returned each time.
     *
     * This is useful for constants that are expensive to instantiate. If added
     * globally through this method, only a single instance will ever be
     * created.
     *
     * @param ctor the value to add as a global constant
     * @return an expression referring to the constant
     */
    Expression* addGlobalConstant(Ctor* ctor);

private:
    bool _compileModule(hilti::declaration::Module* module, int pass, codegen::ASTInfo* info);
    void _updateDeclarations(visitor::MutatingPostOrder* v, hilti::declaration::Module* module);
    void _compileParserRegistration(const ID& public_id, const ID& struct_id, type::Unit* unit);

    Builder* _builder;
    codegen::GrammarBuilder _gb;
    codegen::ParserBuilder _pb;
    codegen::ASTInfo _ast_info;

    std::vector<hilti::declaration::Property> _properties;
    std::map<UnqualifiedType*, UnqualifiedType*> _type_mappings;
    std::map<std::string, std::pair<hilti::util::Uniquer<ID>, hilti::util::Cache<std::string, Expression*>>>
        _global_constants; // map type of ctor to type-specific uniquer and cache

    hilti::declaration::Module* _hilti_module = nullptr;
    Declarations _new_decls;
    hilti::util::Uniquer<std::string> _uniquer;
};

} // namespace spicy::detail
