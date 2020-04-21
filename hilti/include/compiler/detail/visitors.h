// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>

namespace hilti {

class Unit;

namespace printer {
class Stream;
} // namespace printer

namespace detail {

/**Performs imports for an AST. */
std::set<context::ModuleIndex> importModules(const Node& root, Unit* unit);

/**
 * Prints an AST as HILTI source code. This consults any installed plugin
 * `print_ast` hooks.
 */
void printAST(const Node& root, std::ostream& out, bool compact = false);

/**
 * Prints an AST as HILTI source code. This consults any installed plugin
 * `print_ast` hooks.
 */
void printAST(const Node& root, printer::Stream& stream); // NOLINT

/** Returns a string with the prototype for an operator for display. */
std::string renderOperatorPrototype(const expression::UnresolvedOperator& o);

/** Returns a string with the prototype for an operator for display. */
std::string renderOperatorPrototype(const expression::ResolvedOperator& o);

/** Returns a string with an instantiated  operator for display. */
std::string renderOperatorInstance(const expression::UnresolvedOperator& o);

/** Returns a string with an instantiated  operator for display. */
std::string renderOperatorInstance(const expression::ResolvedOperator& o);

/** Prints a debug dump of a node, including its childrens. */
void renderNode(const Node& n, std::ostream& out, bool include_scopes = false);
void renderNode(const Node& n, logging::DebugStream stream, bool include_scopes = false);

/**
 * Resets dynamically built state in an AST. Currently, this clears all the
 * scopes and any errors.
 */
void resetNodes(Node* root);

/**
 * Clears any errors currentluy set in an AST.
 */
void clearErrors(Node* root);

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void buildScopes(const std::vector<std::pair<ID, NodeRef>>& modules, Unit* unit);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool resolveIDs(Node* root, Unit* unit);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool resolveOperators(Node* root, Unit* unit);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
std::optional<Ctor> coerceCtor(Ctor c, const Type& dst, bitmask<CoercionStyle> style);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
std::optional<Type> coerceType(Type t, const Type& dst, bitmask<CoercionStyle> style);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool applyCoercions(Node* root, Unit* unit);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validateAST(Node* root);


} // namespace detail
} // namespace hilti
