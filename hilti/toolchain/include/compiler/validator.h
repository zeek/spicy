// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>

namespace hilti {

namespace detail::cfg {
class Cache;
}

namespace validator {

/** Mix-in class for AST validators providing some common helpers. */
class VisitorMixIn {
public:
    VisitorMixIn(Builder* builder) : _builder(builder) {}

    /** Returns the builder associated with the validator. */
    auto builder() const { return _builder; }

    /** Returns the AST context associated with the validator. */
    auto context() const { return _builder->context(); }

    /* Emit a deprecation warning with the given node. */
    void deprecated(const std::string& msg, const Location& l) const;

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

    /** Validates if provided type arguments match a type's expectation. */
    void checkTypeArguments(const node::Range<Expression>& have, const node::Set<type::function::Parameter>& want,
                            Node* n, bool allow_no_arguments = false, bool do_not_check_types = false);

private:
    Builder* _builder;
    int _errors = 0;
};

namespace detail {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validatePre(Builder* builder, ASTRoot* root);

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void validatePost(Builder* builder, ASTRoot* root);

/** Implements a final HILTI-level validator performing additional checks that require CFGs. */
void validateCFG(Builder* builder, ASTRoot* root, ::hilti::detail::cfg::Cache* cfg_cache);

} // namespace detail
} // namespace validator
} // namespace hilti
