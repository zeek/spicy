// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

namespace hilti::statement {

/** AST node for a `if` statement. */
class If : public Statement {
public:
    auto init() const { return child<hilti::declaration::LocalVariable>(0); }
    auto condition() const { return child<::hilti::Expression>(1); }
    auto true_() const { return child<hilti::Statement>(2); }
    auto false_() const { return child<Statement>(3); }

    void setCondition(ASTContext* ctx, const ExpressionPtr& c) { setChild(ctx, 1, c); }

    static auto create(ASTContext* ctx, const DeclarationPtr& init, const ExpressionPtr& cond,
                       const StatementPtr& true_, const StatementPtr& false_, Meta meta = {}) {
        return std::shared_ptr<If>(new If(ctx, {init, cond, true_, false_}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, const ExpressionPtr& cond, const StatementPtr& true_,
                       const StatementPtr& false_, Meta meta = {}) {
        return std::shared_ptr<If>(new If(ctx, {nullptr, cond, true_, false_}, std::move(meta)));
    }

protected:
    If(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {
        if ( child(0) && ! child(0)->isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'if' must be a local declaration");
    }

    HILTI_NODE_1(statement::If, Statement, final);
};

} // namespace hilti::statement
