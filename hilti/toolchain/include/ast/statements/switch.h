// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

class Switch;

namespace switch_ {

using Default = struct {};

/**
 * AST node for a switch case type.
 *
 * Note that internally, we store the expressions in a preprocessed matter:
 * `E` turns into `<id> == E`, where ID is selected to match the code
 * generator's output. Doing this allows coercion for the comparison to
 * proceed normally. The preprocessing happens at the time the `Case` gets
 * added to a `Switch` statement, and the new versions are stored separately
 * from the original expressions.
 */
class Case : public NodeBase {
public:
    Case(hilti::Expression expr, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body), std::move(expr)), std::move(m)), _end_exprs(2) {}
    Case(std::vector<hilti::Expression> exprs, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body), std::move(exprs)), std::move(m)),
          _end_exprs(static_cast<int>(children().size())) {}
    Case(Default /*unused*/, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body)), std::move(m)), _end_exprs(1) {}
    Case() = default;

    auto expressions() const { return children<hilti::Expression>(1, _end_exprs); }
    auto preprocessedExpressions() const { return children<hilti::Expression>(_end_exprs, -1); }
    const auto& body() const { return child<Statement>(0); }

    bool isDefault() const { return expressions().empty(); }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return children()[0]; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Case& other) const { return expressions() == other.expressions() && body() == other.body(); }

private:
    friend class hilti::statement::Switch;

    void _preprocessExpressions(const std::string& id) {
        children().erase(children().begin() + _end_exprs, children().end());
        children().reserve(static_cast<size_t>(_end_exprs) * 2); // avoid resizing/invalidation below on emplace

        for ( const auto& e : expressions() ) {
            hilti::Expression n =
                expression::UnresolvedOperator(operator_::Kind::Equal, {expression::UnresolvedID(ID(id)), e}, e.meta());

            children().emplace_back(std::move(n));
        }
    }

    int _end_exprs{};
};

inline Node to_node(Case c) { return Node(std::move(c)); }

} // namespace switch_

/** AST node for a "switch" statement. */
class Switch : public NodeBase, public hilti::trait::isStatement {
public:
    Switch(hilti::Expression cond, const std::vector<switch_::Case>& cases, const Meta& m = Meta())
        : Switch(hilti::declaration::LocalVariable(hilti::ID("__x"), std::move(cond), true, m), cases, m) {}

    Switch(const hilti::Declaration& cond, const std::vector<switch_::Case>& cases, Meta m = Meta())
        : NodeBase(nodes(cond, cases), std::move(m)) {
        if ( ! cond.isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'switch' must be a local declaration");
    }

    const auto& condition() const { return children()[0].as<hilti::declaration::LocalVariable>(); }
    auto conditionRef() const { return NodeRef(children()[0]); }
    auto cases() const { return children<switch_::Case>(1, -1); }

    hilti::optional_ref<const switch_::Case> default_() const {
        for ( const auto& c : children<switch_::Case>(1, -1) ) {
            if ( c.isDefault() )
                return c;
        }
        return {};
    }

    void preprocessCases() {
        if ( _preprocessed )
            return;

        for ( auto c = children().begin() + 1; c != children().end(); c++ )
            c->as<switch_::Case>()._preprocessExpressions(condition().id());

        _preprocessed = true;
    }

    bool operator==(const Switch& other) const {
        return condition() == other.condition() && default_() == other.default_() && cases() == other.cases();
    }

    /** Internal method for use by builder API only. */
    auto& _lastCaseNode() { return children().back(); }

    /** Internal method for use by builder API only. */
    void _addCase(switch_::Case case_) {
        addChild(std::move(case_));
        _preprocessed = false;
    }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    bool _preprocessed = false;
};

} // namespace hilti::statement
