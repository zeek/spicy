// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <vector>

#include <hilti/ast/forward.h>

#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/pir.h>

namespace spicy::detail::pir {

/**
 * Discovers candidate public roots (ordinary functions and parser units)
 * across resolved `.spicy` modules whose `skipImplementation()` is false, in
 * source order. Discovery is read-only; it does not judge whether a root is
 * representable.
 */
std::vector<hilti::Declaration*> discoverRoots(const hilti::ASTContext& ctx);

/**
 * Attempts to lower every discovered root into `package`, in order. Stops
 * and returns the first unsupported feature encountered, if any; the caller
 * must discard `package` in that case rather than treat it as a complete
 * representation.
 */
std::optional<UnsupportedFeature> lowerRoots(const std::vector<hilti::Declaration*>& roots, ir::Package& package);

} // namespace spicy::detail::pir
