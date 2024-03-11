// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/tuple.h>

namespace hilti::ctor {

/** AST node for a tuple ctor. */
class Tuple : public Ctor {
public:
    auto value() const { return children<Expression>(1, {}); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    static auto create(ASTContext* ctx, const Expressions& exprs, Meta meta = {}) {
        auto type = _inferType(ctx, exprs, meta);
        return ctx->make<Tuple>(ctx, node::flatten(type, exprs), std::move(meta));
    }

protected:
    Tuple(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Tuple, Ctor, final);

private:
    static QualifiedType* _inferType(ASTContext* ctx, const Expressions& exprs, const Meta& meta) {
        for ( const auto& e : exprs ) {
            if ( ! e->isResolved() )
                return QualifiedType::createAuto(ctx, meta);
        }

        QualifiedTypes types;
        types.reserve(exprs.size());
        for ( const auto& e : exprs )
            types.emplace_back(e->type());

        return QualifiedType::create(ctx, type::Tuple::create(ctx, types, meta), Constness::Const, meta);
    }
};
} // namespace hilti::ctor
