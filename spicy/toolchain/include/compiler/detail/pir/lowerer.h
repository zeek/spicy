// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <vector>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/forward.h>

#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/pir.h>

namespace spicy::detail::pir {

/** Discovery output of public roots (functions/units). */
struct RootDiscovery {
    std::vector<hilti::Declaration*> roots;
    std::vector<hilti::ast::TypeIndex> units_with_external_hooks;
    std::optional<UnsupportedFeature> unrepresented_content;
};

RootDiscovery discoverRoots(const hilti::ASTContext& ctx);

/**
 * Attempts to lower every discovered root into `package`, in order. Stops
 * and returns the first unsupported feature encountered, if any.
 *
 * If there are any unsupported features, the resulting `package` is invalid.
 */
std::optional<UnsupportedFeature> lowerRoots(const RootDiscovery& discovery, ir::Package& package);

} // namespace spicy::detail::pir
