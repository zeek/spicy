// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <vector>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/forward.h>

#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/pir.h>

namespace spicy::detail::pir {

/**
 * Read-only discovery of candidate public roots (ordinary functions and parser units) across
 * resolved `.spicy` modules whose `skipImplementation()` is false, in source order, plus the set
 * of unit types that have at least one external (module-level `on Unit::...`) hook anywhere in the
 * AST. External hooks are not children of `type::Unit::items()`, so a lowerer that only inspects a
 * candidate unit's own items cannot see them; discovery walks the whole AST once, up front, so
 * that information is available before any unit is judged representable.
 */
struct RootDiscovery {
    std::vector<hilti::Declaration*> roots;
    std::vector<hilti::ast::TypeIndex> units_with_external_hooks;
};

RootDiscovery discoverRoots(const hilti::ASTContext& ctx);

/**
 * Attempts to lower every discovered root into `package`, in order. Stops
 * and returns the first unsupported feature encountered, if any; the caller
 * must discard `package` in that case rather than treat it as a complete
 * representation.
 */
std::optional<UnsupportedFeature> lowerRoots(const RootDiscovery& discovery, ir::Package& package);

} // namespace spicy::detail::pir
