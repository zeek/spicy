// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>

namespace hilti::detail::optimizer {

/**
 * Applies optimizations to an AST. The AST must have been fully processed
 * before running optimization.
 */
void optimize(Builder* builder, const ASTRootPtr& root);

} // namespace hilti::detail::optimizer
