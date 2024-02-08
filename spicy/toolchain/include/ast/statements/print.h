// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

#include <spicy/ast/forward.h>

namespace spicy::statement {

/** AST node for a `break` statement. */
class Print : public Statement {
public:
    auto expressions() const { return children<hilti::Expression>(0, {}); }

    static auto create(ASTContext* ctx, Expressions expressions, Meta meta = {}) {
        return std::shared_ptr<Print>(new Print(ctx, std::move(expressions), std::move(meta)));
    }

protected:
    Print(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(spicy, Print)
};

} // namespace spicy::statement
