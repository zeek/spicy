// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>

#include "spicy/ast/aliases.h"

namespace spicy {

/**
 * Parses a Spicy source file into an AST.
 *
 * @param in stream to read from
 * @param filename path associated with the input
 *
 * Returns: The parsed AST, or a corresponding error if parsing failed.
 */
hilti::Result<hilti::Node> parseSource(std::istream& in, const std::string& filename);

/**
 * Parses a single Spicy expression into a corresponding AST.
 *
 * @param expr expression to parse.
 * @param m optional meta information to associate with expression
 *
 * Returns: The parsed expression, or a corresponding error if parsing failed.
 */
hilti::Result<Expression> parseExpression(const std::string& expr, const Meta& m = Meta());

} // namespace spicy
