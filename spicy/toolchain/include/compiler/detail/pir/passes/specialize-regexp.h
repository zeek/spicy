// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::passes {

/**
 * The scan that does what `regexp` does, if `regexp` is one case-sensitive pattern of a single byte class, or a single
 * byte, repeated with `*` or `+`. Nothing else qualifies.
 */
std::optional<ir::ScanBytesPayload> recognizeByteScan(const ir::RegExpDecl& regexp);

/** Replaces each `parser.match_regexp` of `function` that `recognizeByteScan()` accepts with `parser.scan_bytes`. */
bool specializeRegExps(ir::Package& package, ir::FunctionId function);

} // namespace spicy::detail::pir::passes
