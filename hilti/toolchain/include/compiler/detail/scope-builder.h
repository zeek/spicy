// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/compiler/unit.h>

namespace hilti::detail::scope_builder {

/**
 * Implements the corresponding functionality for the default HILTI compiler plugin.
 *
 * The result indicates whether any scopes were modified during the process.

 * Note that this doesn't report if there are pre-existing IDs that weren't
 * accessed at all during the current run. It will return "unchanged" in that
 * case if no changes were made beyond such IDs.
 *
 * @param builder the builder to use
 * @param root root node to process.
 * @return true if any scopes were modified, false otherwise.
 */
bool build(Builder* builder, Node* node);


} // namespace hilti::detail::scope_builder
