// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>

namespace hilti::detail::optimizer {

/**
 * Applies optimizations to an AST. The AST must have been fully processed
 * before running optimization.
 */
bool optimize(Builder* builder, ASTRoot* root, bool first);

} // namespace hilti::detail::optimizer
