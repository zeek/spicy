// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
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

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, const QualifiedTypePtr& t) { setChild(ctx, 0, t); }

    void setValue(ASTContext* ctx, Expressions exprs) {
        removeChildren(1, {});
        addChildren(ctx, std::move(exprs));
    }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& etype, Expressions exprs, const Meta& meta = {}) {
        auto stype = QualifiedType::create(ctx, type::Vector::create(ctx, etype, meta), Constness::NonConst, meta);
        return std::shared_ptr<Vector>(new Vector(ctx, node::flatten(stype, std::move(exprs)), meta));
    }

    static auto create(ASTContext* ctx, Expressions exprs, const Meta& meta = {}) {
        // bool is just an arbitrary place-holder type for empty values.
        auto etype = exprs.empty() ?
                         QualifiedType::create(ctx, type::Bool::create(ctx, meta), Constness::NonConst, meta) :
                         QualifiedType::createAuto(ctx, meta);
        return create(ctx, etype, std::move(exprs), meta);
    }

protected:
    Vector(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Vector)
};

} // namespace hilti::ctor
