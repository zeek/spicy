// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/base/logger.h>

namespace hilti::detail::ast_dumper {

/**
 * Prints out a debug representation of an AST node to a debug stream. The
 * output will include all the node's children recursively.
 *
 * @param out stream to print to
 * @param node the node
 * @param include_scopes if true, include a dump of each node's identifier
 *        scope
 */
void dump(std::ostream& out, const NodePtr& node, bool include_scopes = false);

/**
 * Log a debug representation of an AST node to a debug stream. The output
 * will include all the node's children recursively.
 *
 * @param stream
 * @param node the node
 * @param include_scopes if true, include a dump of each node's identifier
 *        scope
 */
void dump(logging::DebugStream stream, const NodePtr& node, bool include_scopes = false);

} // namespace hilti::detail::ast_dumper
