// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/**
 * AST node for grouping one or more expressions inside parentheses.
 * Optionally, the grouping may declare a local variable as well that will be
 * valid for usage inside the grouping's contained expression. If there are
 * mote than one expression, they will all be evaluated in order, with the
 * value of the last expression being the value of the grouping.
 */
class Grouping : public Expression {
public:
    auto local() const { return child<declaration::LocalVariable>(0); }
    auto expressions() const { return children<Expression>(1, {}); }

    QualifiedType* type() const final {
        if ( auto* last = child<Expression>(-1) )
            return last->type();
        else
            return nullptr;
    }

    void setExpressions(ASTContext* ctx, Expressions exprs) {
        removeChildren(1, {});
        addChildren(ctx, std::move(exprs));
    }

    static auto create(ASTContext* ctx, Expressions exprs, Meta meta = {}) {
        Nodes nodes = {nullptr};
        nodes.insert(nodes.end(), exprs.begin(), exprs.end());
        return ctx->make<Grouping>(ctx, std::move(nodes), std::move(meta));
    }

    static auto create(ASTContext* ctx, declaration::LocalVariable* local, Expressions exprs, Meta meta = {}) {
        Nodes nodes = {local};
        nodes.insert(nodes.end(), exprs.begin(), exprs.end());
        return ctx->make<Grouping>(ctx, std::move(nodes), std::move(meta));
    }

protected:
    Grouping(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Grouping, Expression, final);
};

} // namespace hilti::expression
