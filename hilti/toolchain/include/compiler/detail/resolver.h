// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/base/result.h>

namespace hilti::detail::resolver {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool resolve(Builder* builder, Node* node);

/**
 * Implements just the type and expression coercion pass of the resolver. This
 * can be run on any subpart of the AST. It assumes that expressions and types
 * have already been resolved except for coercions. This makes as many passes
 * over the AST as needed until all possible coercions have been applied.
 *
 * @param builder the builder to use
 * @param node root node to process.
 * @return true if any changes were made
 */
bool coerce(Builder* builder, Node* node);

} // namespace hilti::detail::resolver
