// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

class SetLocation : public Statement {
public:
    auto expression() const { return child<::hilti::Expression>(0); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, Meta meta = {}) {
        return std::shared_ptr<SetLocation>(new SetLocation(ctx, {expr}, std::move(meta)));
    }

protected:
    SetLocation(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, SetLocation)
};

} // namespace hilti::statement
