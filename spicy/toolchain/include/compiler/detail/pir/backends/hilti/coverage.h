// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <vector>

#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/pir.h>

// This namespace is deliberately named `hilti`, nested under `spicy::detail::pir::backend`.
// Because that shadows the top-level `::hilti` namespace within its own scope, every reference to
// a `::hilti`-namespace name inside this namespace (and its `.cc`) must be written with the
// leading `::`.

namespace spicy::detail::pir::backend::hilti {

/**
 * Checks whether `package` is entirely within this backend's accepted subset: a public unit with
 * exactly one plain `uint8` field and no parameters, attributes, or hooks, parsed by a single
 * unsigned width-8 network-byte-order read. An empty result means the whole package is supported;
 * a non-empty result reports every coverage gap found and means the caller must not attempt to
 * lower any part of it.
 *
 * This is a target-coverage judgment, not a well-formedness check: `package` is assumed to have
 * already passed the PIR verifier. A coverage gap here is not a verifier failure; it is a signal
 * to fall back to the standard code generator for the complete compilation.
 */
std::vector<UnsupportedFeature> checkCoverage(const ir::Package& package);

} // namespace spicy::detail::pir::backend::hilti
