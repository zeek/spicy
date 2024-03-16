// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>

namespace hilti::validator {

/** Mix-in class for AST validators providing some common helpers. */
class VisitorMixIn {
public:
    VisitorMixIn(Builder* builder) : _builder(builder) {}

    /** Returns the builder associated with the validator. */
    auto builder() const { return _builder; }

    /** Returns the AST context associated with the validator. */
    auto context() const { return _builder->context(); }

    /* Record error with given node. */
    void error(std::string msg, Node* n, node::ErrorPriority priority = node::ErrorPriority::Normal);

    /** Record error with given node, providing additional context for the error report. */
    void error(std::string msg, std::vector<std::string> context, Node* n,
               node::ErrorPriority priority = node::ErrorPriority::Normal);

    /* Record error with given node but use another's location for reporting. */
    void error(std::string msg, Node* n, const Node* other, node::ErrorPriority priority = node::ErrorPriority::Normal);

    /* Record error with given node but use a custom location for reporting. */
    void error(std::string msg, Node* n, Location l, node::ErrorPriority priority = node::ErrorPriority::Normal);

    /** Returns the number of errors reported so far. */
    auto errors() const { return _errors; }

private:
    Builder* _builder;
    int _errors = 0;
};

namespace detail {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validatePre(Builder* builder, ASTRoot* root);

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validatePost(Builder* builder, ASTRoot* root);

} // namespace detail
} // namespace hilti::validator
