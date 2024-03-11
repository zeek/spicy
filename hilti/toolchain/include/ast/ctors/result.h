// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/error.h>
#include <hilti/ast/types/result.h>

namespace hilti::ctor {

/** AST node for a `optional` ctor. */
class Result : public Ctor {
public:
    QualifiedType* dereferencedType() const { return type()->type()->as<type::Result>()->dereferencedType(); }

    Expression* value() const {
        const auto& e = child<Expression>(1);

        if ( ! e->type()->type()->isA<type::Error>() )
            return e;
        else
            return {};
    }

    Expression* error() const {
        const auto& e = child<Expression>(1);

        if ( e->type()->type()->isA<type::Error>() )
            return e;
        else
            return {};
    }

    QualifiedType* type() const final {
        if ( auto e = child<QualifiedType>(0) )
            return e;
        else
            return child<Expression>(1)->type();
    }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    static auto create(ASTContext* ctx, Expression* expr, const Meta& meta = {}) {
        return ctx->make<Result>(ctx,
                                 {
                                     nullptr,
                                     expr,
                                 },
                                 meta);
    }

protected:
    Result(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Result, Ctor, final);
};

} // namespace hilti::ctor
