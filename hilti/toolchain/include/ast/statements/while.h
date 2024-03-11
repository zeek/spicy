// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

namespace hilti::statement {

/** AST node for a `while` statement. */
class While : public Statement {
public:
    auto init() const { return child<declaration::LocalVariable>(0); }
    auto condition() const { return child<::hilti::Expression>(1); }
    auto body() const { return child<hilti::Statement>(2); }
    auto else_() const { return child<Statement>(3); }

    void setCondition(ASTContext* ctx, hilti::Expression* c) { setChild(ctx, 1, c); }
    void removeElse(ASTContext* ctx) { setChild(ctx, 3, nullptr); }

    static auto create(ASTContext* ctx, hilti::Declaration* init, hilti::Expression* cond, Statement* body,
                       Statement* else_ = nullptr, Meta meta = {}) {
        return ctx->make<While>(ctx, {init, cond, body, else_}, std::move(meta));
    }

    static auto create(ASTContext* ctx, hilti::Expression* cond, Statement* body, Meta meta = {}) {
        return create(ctx, nullptr, cond, body, nullptr, std::move(meta));
    }
    static auto create(ASTContext* ctx, hilti::Expression* cond, Statement* body, Statement* else_ = nullptr,
                       Meta meta = {}) {
        return create(ctx, nullptr, cond, body, else_, std::move(meta));
    }

protected:
    While(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {
        if ( child(0) && ! child(0)->isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'while' must be a local declaration");
    }

    HILTI_NODE_1(statement::While, Statement, final);
};

} // namespace hilti::statement
