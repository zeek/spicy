// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::passes {

/**
 * Folds non-overflowing `core.add`, `core.equal`, and `core.convert` of constants in place, and turns a branch or
 * switch on a constant into a jump, erasing the blocks that become unreachable.
 */
bool foldConstants(ir::Package& package, ir::FunctionId function);

} // namespace spicy::detail::pir::passes
