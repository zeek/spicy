// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

class Switch;

namespace switch_ {

using Default = struct {};

/**
 * AST node for a switch case type.
 *
 * Note that internally, we store the expressions in a preprocessed matter:
 * `E` turns into `<id> == E`, where ID is selected to match the code
 * generator's output. Doing this allows coercion for the comparision to
 * proceed normally. The preprocessing happens at the time the `Case` gets
 * added to a `Switch` statement, and the new versions are stored separately
 * from the original expressions.
 */
class Case : public NodeBase {
public:
    Case(hilti::Expression expr, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body), std::move(expr)), std::move(m)), _end_exprs(2) {}
    Case(std::vector<hilti::Expression> exprs, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body), std::move(exprs)), std::move(m)), _end_exprs(childs().size()) {}
    Case(Default /*unused*/, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(body)), std::move(m)), _end_exprs(1) {}
    Case() = default;

    auto expressions() const { return childs<hilti::Expression>(1, _end_exprs); }
    auto preprocessedExpressions() const { return childs<hilti::Expression>(_end_exprs, -1); }
    const auto& body() const { return child<Statement>(0); }

    bool isDefault() const { return expressions().empty(); }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return childs()[0]; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Case& other) const { return expressions() == other.expressions() && body() == other.body(); }

    /**
     * Replaces a case's expresssions.
     *
     * @param c case to replace expressions in
     * @param exprs new expressions
     * @return new case that is a duplicate of *c* but has its expressions replaced with *expr*
     */
    static Case setExpressions(Case c, std::vector<hilti::Expression> exprs) {
        c.childs() = hilti::nodes(c._bodyNode(), std::move(exprs));
        return c;
    }

private:
    friend class hilti::statement::Switch;

    void _addPreprocessedExpression(hilti::Expression e) { childs().emplace_back(std::move(e)); }

    int _end_exprs{};
};

inline Node to_node(Case c) { return Node(std::move(c)); }

} // namespace switch_

/** AST node for a "switch" statement. */
class Switch : public NodeBase, public hilti::trait::isStatement {
public:
    Switch(hilti::Expression cond, const std::vector<switch_::Case>& cases, Meta m = Meta())
        : NodeBase(nodes(node::none, std::move(cond), cases), std::move(m)) {
        _preprocessCases("__x");
    }

    Switch(const hilti::Declaration& init, hilti::Expression cond, const std::vector<switch_::Case>& cases,
           Meta m = Meta())
        : NodeBase(nodes(init, std::move(cond), cases), std::move(m)) {
        if ( ! init.isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'switch' must be a local declaration");
        _preprocessCases(init.id());
    }

    auto init() const { return childs()[0].tryReferenceAs<hilti::Declaration>(); }
    const auto& expression() const { return childs()[1].as<hilti::Expression>(); }
    auto type() const {
        if ( auto i = init() )
            return i->as<declaration::LocalVariable>().type();

        return expression().type();
    }

    auto cases() const {
        std::vector<switch_::Case> cases;
        for ( auto& c : childs<switch_::Case>(2, -1) ) {
            if ( ! c.isDefault() )
                cases.push_back(c);
        }

        return cases;
    }

    auto caseNodes() { return nodesOfType<switch_::Case>(); }

    std::optional<switch_::Case> default_() const {
        for ( auto& c : childs<switch_::Case>(2, -1) ) {
            if ( c.isDefault() )
                return c;
        }
        return {};
    }

    bool operator==(const Switch& other) const {
        return init() == other.init() && expression() == other.expression() && default_() == other.default_() &&
               cases() == other.cases();
    }

    /** Internal method for use by builder API only. */
    auto& _lastCaseNode() { return childs().back(); }

    /** Internal method for use by builder API only. */
    void _addCase(switch_::Case case_) {
        for ( const auto& c : case_.expressions() )
            case_._addPreprocessedExpression(expression::UnresolvedOperator(operator_::Kind::Equal,
                                                                            {expression::UnresolvedID(ID(_id)), c},
                                                                            c.meta()));

        addChild(std::move(case_));
    }


    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    void _preprocessCases(const std::string& id) {
        _id = id;

        for ( uint64_t i = 2; i < childs().size(); i++ ) {
            auto& case_ = childs()[i].as<switch_::Case>();
            for ( const auto& c : case_.expressions() )
                case_._addPreprocessedExpression(expression::UnresolvedOperator(operator_::Kind::Equal,
                                                                                {expression::UnresolvedID(ID(id)), c},
                                                                                c.meta()));
        }
    }

    std::string _id;
};

} // namespace statement
} // namespace hilti
