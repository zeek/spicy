// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/type.h>
#include <hilti/base/logger.h>
#include <hilti/base/visitor-types.h>

namespace hilti {

/**
 * Parses a HILTI source file into an AST.
 *
 * @param in stream to read from
 * @param filename path associated with the input
 *
 * Returns: The parsed AST, or a corresponding error if parsing failed.
 */
Result<Node> parseSource(std::istream& in, const std::string& filename);

/**
 * Prints out a debug representation of an AST node to a debug stream. The
 * output will include all the node's children recursively.
 *
 * @param out stream to print to
 * @param node the node
 * @param include_scopes if true, include a dump of each node's identifier
 *        scope
 */
extern void render(std::ostream& out, const Node& node, bool include_scopes = false);

/**
 * Log a debug representation of an AST node to a debug stream. The output
 * will include all the node's children recursively.
 *
 * @param stream
 * @param node the node
 * @param include_scopes if true, include a dump of each node's identifier
 *        scope
 */
extern void render(logging::DebugStream stream, const Node& node, bool include_scopes = false);

/**
 * Print out an AST node as HILTI source.
 *
 * @note Usually, this function should be used on an AST's root node (i.e.,
 * the module). The function accepts other nodes, but may not always produce
 * correct code for them.
 *
 * @param out stream to print to
 * @param node the node
 * @param compact if true, print a compact one-line representation (e.g., for
 *        use in error messages)
 */
inline void print(std::ostream& out, const Node& node, bool compact = false) { node.print(out, compact); }

} // namespace hilti
