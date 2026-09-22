// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <variant>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/module.h>

#include <spicy/compiler/detail/pir/backends/hilti/coverage.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/pir.h>

// This namespace is deliberately named `hilti`, nested under `spicy::detail::pir::backend`.
// Because that shadows the top-level `::hilti` namespace within its own scope, every reference to
// a `::hilti`-namespace name inside this namespace (and its `.cc`) must be written with the
// leading `::`.

namespace spicy::detail::pir::backend::hilti {

/**
 * Either the detached synthetic HILTI module produced by `lower()`, or the coverage gaps that
 * kept it from lowering `package` at all (see `checkCoverage()`).
 */
using LoweringResult = std::variant<::hilti::declaration::Module*, Unsupported>;

/**
 * Lowers `package` into one deterministic synthetic HILTI module implementing every parser root
 * directly. Coverage is whole-package and atomic: if any part of `package` falls outside
 * `checkCoverage()`'s accepted subset, this returns `Unsupported` and constructs no declaration
 * reachable from `builder`'s AST context.
 *
 * The returned module is fully built but detached from `builder`'s context; attaching it (and
 * choosing not to run the legacy code generator for the same compilation) is the caller's
 * responsibility.
 */
LoweringResult lower(::hilti::Builder& builder, const ir::Package& package);

} // namespace spicy::detail::pir::backend::hilti
