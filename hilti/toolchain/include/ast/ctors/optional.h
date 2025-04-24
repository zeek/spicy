// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/optional.h>

namespace hilti::ctor {

/** AST node for a `optional` ctor. */
class Optional : public Ctor {
public:
    Expression* value() const { return child<Expression>(1); }
    QualifiedType* dereferencedType() const { return type()->type()->as<type::Optional>()->dereferencedType(); }

    QualifiedType* type() const final {
        if ( auto* e = child<QualifiedType>(0) )
            return e;
        else
            return child<Expression>(1)->type();
    }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    /** Constructs a set value. */
    static auto create(ASTContext* ctx, Expression* expr, const Meta& meta = {}) {
        return ctx->make<Optional>(ctx,
                                   {
                                       QualifiedType::create(ctx, type::Auto::create(ctx), Constness::Const),
                                       expr,
                                   },
                                   meta);
    }

    /** Constructs an unset value of type `t`. */
    static auto create(ASTContext* ctx, QualifiedType* type, const Meta& meta = {}) {
        return ctx->make<Optional>(ctx,
                                   {
                                       QualifiedType::create(ctx, type::Optional::create(ctx, type), Constness::Const),
                                       nullptr,
                                   },
                                   meta);
    }

protected:
    Optional(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Optional, Ctor, final);
};

} // namespace hilti::ctor
