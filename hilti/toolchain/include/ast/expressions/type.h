// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/type.h>

namespace hilti::expression {

/** AST node for a type expression. */
class Type_ : public Expression {
public:
    auto typeValue() const { return type()->type()->as<type::Type_>()->typeValue(); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, QualifiedType* type, const Meta& meta = {}) {
        return ctx->make<Type_>(ctx,
                                {QualifiedType::create(ctx, type::Type_::create(ctx, type, meta), Constness::Const,
                                                       meta)},
                                meta);
    }

protected:
    Type_(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Type_, Expression, final);
};

} // namespace hilti::expression
