// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/vector.h>

namespace hilti::ctor {

/** AST node for a `vector` ctor. */
class Vector : public Ctor {
public:
    auto elementType() const { return type()->type()->as<type::Vector>()->elementType(); }
    auto value() const { return children<Expression>(1, {}); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    void setValue(ASTContext* ctx, const Expressions& exprs) {
        removeChildren(1, {});
        addChildren(ctx, exprs);
    }

    static auto create(ASTContext* ctx, QualifiedType* etype, const Expressions& exprs, Meta meta = {}) {
        auto stype = QualifiedType::create(ctx, type::Vector::create(ctx, etype, meta), Constness::Mutable, meta);
        return ctx->make<Vector>(ctx, node::flatten(stype, exprs), std::move(meta));
    }

    static auto create(ASTContext* ctx, const Expressions& exprs, Meta meta = {}) {
        // bool is just an arbitrary place-holder type for empty values.
        auto etype = exprs.empty() ?
                         QualifiedType::create(ctx, type::Bool::create(ctx, meta), Constness::Mutable, meta) :
                         QualifiedType::createAuto(ctx, meta);
        return create(ctx, etype, exprs, std::move(meta));
    }

protected:
    Vector(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Vector, Ctor, final);
};

} // namespace hilti::ctor
