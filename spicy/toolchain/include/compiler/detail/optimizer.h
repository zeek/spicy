// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/base/logger.h>

#include <spicy/ast/forward.h>

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream Optimizer("optimizer");
} // namespace spicy::logging::debug

namespace spicy::detail::optimizer {

/** Implements an optimization pass over the resolved Spicy AST before lowering to HILTI. */
bool optimize(Builder* builder, hilti::ASTRoot* root);

} // namespace spicy::detail::optimizer
