// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

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

    /**
     * Returns the index of an expression inside the tuple.
     *
     * @param expr expression to look for
     * @return index of the element, or -1 if not found
     */
    int index(Expression* expr) const {
        for ( int i = 1; std::cmp_less(i, children().size()); i++ ) {
            if ( child(i) == expr )
                return i - 1;
        }

        return -1;
    }

    /**
     * Removes an element from the tuple.
     *
     * @param i index of the element to remove
     * @return the removed expression, now detached from the AST
     */
    Expression* removeElement(int i) {
        assert(! children().empty());
        assert(i >= 0 && std::cmp_less(i, children().size() - 1));
        auto* old = child<Expression>(i + 1);
        old->removeFromParent();
        return old;
    }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    static auto create(ASTContext* ctx, const Expressions& exprs, Meta meta = {}) {
        auto* type = _inferType(ctx, exprs, meta);
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
