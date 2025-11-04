// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/type.h>

namespace hilti::statement {

namespace assert {
/**
 * Tag for `Assert` to constructor to create an assertion expecting an
 * exception to occur.
 */
struct Exception {};
} // namespace assert

/** AST node for an assert statement. */
class Assert : public Statement {
public:
    auto expression() const { return child<::hilti::Expression>(0); }
    auto exception() const { return child<UnqualifiedType>(1); }
    auto message() const { return child<::hilti::Expression>(2); }
    bool expectException() const { return _expect_exception; }

    node::Properties properties() const final {
        auto p = node::Properties{{"expect_exception", _expect_exception}};
        return Statement::properties() + std::move(p);
    }

    void setExpression(ASTContext* ctx, hilti::Expression* c) { setChild(ctx, 0, c); }

    /**
     * Creates an assert statement that expects an expression to evaluate to true at runtime.
     *
     * @param e expression to evaluate at runtime
     * @param msg optional message to report an runtime if assertions fails
     * @param m meta information for AST node
     */
    static auto create(ASTContext* ctx, hilti::Expression* expr, hilti::Expression* msg = nullptr, Meta meta = {}) {
        return ctx->make<Assert>(ctx, {expr, nullptr, msg}, false, std::move(meta));
    }

    /**
     * Creates an assert statement that expects an exception to occur when
     * the expression is evaluated.
     *
     * @param assert::Exception tag to select this constructor
     * @param e expression to evaluate at runtime
     * @param type exception type that's expected to be thrown when *e* is evaluated; unset of any exception
     * @param msg optional message to report an runtime if assertions fails
     * @param m meta information for AST node
     */
    static auto create(ASTContext* ctx, assert::Exception /*unused*/, hilti::Expression* expr, UnqualifiedType* except,
                       hilti::Expression* msg = nullptr, Meta meta = {}) {
        return ctx->make<Assert>(ctx, {expr, except, msg}, true, std::move(meta));
    }

protected:
    Assert(ASTContext* ctx, Nodes children, bool expect_exception, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)), _expect_exception(expect_exception) {}

    HILTI_NODE_1(statement::Assert, Statement, final);

private:
    bool _expect_exception;
};

} // namespace hilti::statement
