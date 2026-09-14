// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::passes {

/** Folds non-overflowing `core.add` constants in place. */
bool foldConstants(ir::Package& package, ir::FunctionId function);

} // namespace spicy::detail::pir::passes
