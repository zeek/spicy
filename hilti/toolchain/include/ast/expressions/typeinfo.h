// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/library.h>

namespace hilti::expression {

/** AST node for a `typeinfo` expression. */
class TypeInfo : public Expression {
public:
    auto expression() const { return child<Expression>(0); }

    QualifiedType* type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, Expression* expr, Meta meta = {}) {
        auto ti = QualifiedType::create(ctx, type::Library::create(ctx, Constness::Const, "hilti::rt::TypeInfo*"),
                                        Constness::Const);
        return ctx->make<TypeInfo>(ctx, {expr, ti}, std::move(meta));
    }

protected:
    TypeInfo(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::TypeInfo, Expression, final);
};

} // namespace hilti::expression
