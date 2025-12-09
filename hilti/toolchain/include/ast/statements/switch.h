// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

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
class Case final : public Node {
public:
    ~Case() final;

    auto expressions() const { return children<hilti::Expression>(1, _end_exprs); }
    auto body() const { return child<Statement>(0); }
    bool isDefault() const { return expressions().empty(); }

    auto preprocessedExpressions() const { return children<hilti::Expression>(_end_exprs, {}); }

    static auto create(ASTContext* ctx, const Expressions& exprs, Statement* body, Meta meta = {}) {
        return ctx->make<Case>(ctx, node::flatten(body, exprs), std::move(meta));
    }

    static auto create(ASTContext* ctx, hilti::Expression* expr, Statement* body, Meta meta = {}) {
        return create(ctx, Expressions{expr}, body, std::move(meta));
    }

    static auto create(ASTContext* ctx, switch_::Default /*unused*/, Statement* body, Meta meta = {}) {
        return create(ctx, Expressions{}, body, std::move(meta));
    }

protected:
    friend class statement::Switch;

    Case(ASTContext* ctx, Nodes children, Meta meta = {}) : Node(ctx, NodeTags, std::move(children), std::move(meta)) {
        _end_exprs = static_cast<int>(Node::children().size());
    }

    void _preprocessExpressions(ASTContext* ctx, const std::string& id) {
        Expressions exprs;
        for ( const auto& e : expressions() ) {
            auto* n = expression::UnresolvedOperator::create(ctx, operator_::Kind::Equal,
                                                             {expression::Name::create(ctx, ID(id), e->meta()), e},
                                                             e->meta());

            exprs.push_back(n);
        }

        removeChildren(_end_exprs, {});
        addChildren(ctx, std::move(exprs));
    }

    std::string _dump() const final;

    HILTI_NODE_0(statement::switch_::Case, final);

private:
    int _end_exprs;
};

using Cases = NodeVector<Case>;

} // namespace switch_

/** AST node for a `switch` statement. */
class Switch : public Statement {
public:
    auto condition() const { return child<declaration::LocalVariable>(0); }
    auto cases() const { return children<switch_::Case>(1, {}); }

    switch_::Case* default_() const {
        for ( const auto& c : cases() ) {
            if ( c->isDefault() )
                return c;
        }

        return nullptr;
    }

    void preprocessCases(ASTContext* ctx) {
        if ( _preprocessed )
            return;

        for ( const auto& c : cases() )
            c->_preprocessExpressions(ctx, condition()->id());

        _preprocessed = true;
    }


    void addCase(ASTContext* ctx, switch_::Case* c) {
        addChild(ctx, c);
        _preprocessed = false;
    }

    static auto create(ASTContext* ctx, hilti::Declaration* cond, const switch_::Cases& cases, Meta meta = {}) {
        return ctx->make<Switch>(ctx, node::flatten(cond, cases), std::move(meta));
    }

    static auto create(ASTContext* ctx, hilti::Expression* cond, const switch_::Cases& cases, Meta meta = {}) {
        return create(ctx, declaration::LocalVariable::create(ctx, ID(HILTI_INTERNAL_ID("x")), cond), cases,
                      std::move(meta));
    }

protected:
    Switch(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {
        if ( ! child(0)->isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'switch' must be a local declaration");
    }

    HILTI_NODE_1(statement::Switch, Statement, final);

private:
    bool _preprocessed = false;
};

} // namespace hilti::statement
