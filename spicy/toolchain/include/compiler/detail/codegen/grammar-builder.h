// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <map>
#include <string>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/all.h>

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream Grammar("grammar");
} // namespace spicy::logging::debug

namespace spicy::detail {

class CodeGen;

namespace codegen {

/** Generates the grammars for all unit types declared in an AST. */
class GrammarBuilder {
public:
    GrammarBuilder(CodeGen* cg) : _cg(cg) {}

    /**
     * Generates the grammar for a unit type. The grammar will afterwards be
     * available through `grammar()`.
     */
    Result<Nothing> run(const type::Unit& unit, Node* node, CodeGen* cg);

    /**
     * Returns the grammar for a unit type. The type must have been computed
     * through `run()` already, otherwise this will abort That's generally
     * done for all AST unit types at the beginning of code generation.
     */
    const Grammar& grammar(const type::Unit& unit);

    CodeGen* cg() const { return _cg; }

private:
    CodeGen* _cg;
    std::map<std::string, Grammar> _grammars;
};

} // namespace codegen
} // namespace spicy::detail
