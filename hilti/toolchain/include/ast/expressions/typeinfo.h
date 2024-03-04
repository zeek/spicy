// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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

    QualifiedTypePtr type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const Meta& meta = {}) {
        auto ti =
            QualifiedType::create(ctx, type::Library::create(ctx, "hilti::rt::TypeInfo const*"), Constness::Const);
        return std::shared_ptr<TypeInfo>(new TypeInfo(ctx, {expr, ti}, meta));
    }

protected:
    TypeInfo(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::TypeInfo, Expression, final);
};

} // namespace hilti::expression
