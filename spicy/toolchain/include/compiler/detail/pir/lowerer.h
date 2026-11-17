// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/forward.h>

#include <spicy/ast/forward.h>
#include <spicy/compiler/detail/pir/ir/diagnostic.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/pir.h>

namespace spicy::detail::codegen {
class Grammar;
} // namespace spicy::detail::codegen

namespace spicy::detail::pir {

/** Discovery output of public roots (functions/units). */
struct RootDiscovery {
    std::vector<hilti::Declaration*> roots;
    std::vector<hilti::declaration::Type*> unit_declarations;
    std::optional<UnsupportedFeature> unrepresented_content;
    std::vector<std::string> cxx_includes;                    /**< `%cxx-include` headers of all modules */
    std::vector<spicy::declaration::UnitHook*> unit_hooks;    /**< external unit hooks; applied to lowered units */
    std::vector<hilti::declaration::GlobalVariable*> globals; /**< module-level variables, all lowered */
    std::vector<std::pair<hilti::declaration::Function*, ir::InitPhase>> initializers; /**< in source order */
};

RootDiscovery discoverRoots(const hilti::ASTContext& ctx);

/** Adds a source span for `loc` to the package; an unset location gives an invalid span. */
ir::SourceSpanId internSpan(ir::Package& package, const hilti::Location& loc);

/**
 * Rejects the look-ahead decisions of a unit's grammar that one token cannot make: alternatives that can start with the
 * same token, no token at all, or a non-terminal. Source spans for the diagnostics are added to `package`.
 *
 * @param grammar a grammar built without legacy's own check
 * @return one error per undecidable look-ahead token, with notes where each alternative can start with it
 */
std::vector<ir::Diagnostic> checkLookAheads(const codegen::Grammar& grammar, ir::Package& package);

/**
 * Attempts to lower every discovered root into `package`, in order. Stops
 * and returns the first unsupported feature encountered, if any.
 *
 * Foreign declarations that only the target can implement are reported in `bindings`.
 *
 * If there are any unsupported features, the resulting `package` is invalid.
 */
std::optional<UnsupportedFeature> lowerRoots(const RootDiscovery& discovery,
                                             ir::Package& package,
                                             std::vector<TargetBinding>& bindings);

} // namespace spicy::detail::pir
