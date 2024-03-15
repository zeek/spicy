// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for a constructor expression. */
class Ctor : public Expression {
public:
    auto ctor() const { return child<hilti::Ctor>(0); }

    QualifiedType* type() const final { return ctor()->type(); }

    static auto create(ASTContext* ctx, hilti::Ctor* ctor, Meta meta = {}) {
        return ctx->make<Ctor>(ctx, {ctor}, std::move(meta));
    }

protected:
    Ctor(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Ctor, Expression, final);
};

} // namespace hilti::expression
