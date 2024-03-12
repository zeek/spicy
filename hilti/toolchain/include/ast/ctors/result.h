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
    QualifiedTypePtr dereferencedType() const { return type()->type()->as<type::Result>()->dereferencedType(); }

    ExpressionPtr value() const {
        const auto& e = child<Expression>(1);

        if ( ! e->type()->type()->isA<type::Error>() )
            return e;
        else
            return {};
    }

    ExpressionPtr error() const {
        const auto& e = child<Expression>(1);

        if ( e->type()->type()->isA<type::Error>() )
            return e;
        else
            return {};
    }

    QualifiedTypePtr type() const final {
        if ( auto e = child(0) )
            return child<QualifiedType>(0);
        else
            return child<Expression>(1)->type();
    }

    void setType(ASTContext* ctx, const QualifiedTypePtr& t) { setChild(ctx, 0, t); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const Meta& meta = {}) {
        return std::shared_ptr<Result>(new Result(ctx,
                                                  {
                                                      nullptr,
                                                      expr,
                                                  },
                                                  meta));
    }

protected:
    Result(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Result, Ctor, final);
};

} // namespace hilti::ctor
