// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/list.h>

namespace hilti::ctor {

/** AST node for a `list` ctor. */
class List : public Ctor {
public:
    auto elementType() const { return type()->type()->as<type::List>()->elementType(); }
    auto value() const { return children<Expression>(1, {}); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    void setValue(ASTContext* ctx, Expressions exprs) {
        removeChildren(0, {});
        addChild(ctx, QualifiedType::createAuto(ctx, meta()));
        addChildren(ctx, std::move(exprs));
    }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    static auto create(ASTContext* ctx, QualifiedType* etype, Expressions exprs, Meta meta = {}) {
        auto stype = QualifiedType::create(ctx, type::List::create(ctx, etype, meta), Constness::Const, meta);
        return ctx->make<List>(ctx, node::flatten(stype, std::move(exprs)), std::move(meta));
    }

    static auto create(ASTContext* ctx, Expressions exprs, Meta meta = {}) {
        // Bool is just an arbitrary place-holder type for empty values.
        auto etype = exprs.empty() ? QualifiedType::create(ctx, type::Bool::create(ctx, meta), Constness::Const, meta) :
                                     QualifiedType::createAuto(ctx, meta);
        return create(ctx, etype, std::move(exprs), std::move(meta));
    }

protected:
    List(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::List, Ctor, final);
};

} // namespace hilti::ctor
