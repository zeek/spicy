// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/compiler/unit.h>

namespace hilti::detail::scope_builder {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void build(Builder* builder, Node* node);

/**
 * Builds up the scope like build(), but also reports whether any changes have
 * been made during the process compared to how the scopes looked like before.
 *
 * Note this doesn't report if there are pre-existing IDs that weren't accessed
 * at all during the current run. It will return "unchanged" in that case if no
 * changes were made beyond such IDs.
 *
 * @return true if any scopes were modified, false otherwise.
 *
 * TODO: Merge this with build() above.
 */
bool buildToValidate(Builder* builder, Node* node);

} // namespace hilti::detail::scope_builder
