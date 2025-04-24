// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/map.h>

namespace hilti::ctor {

namespace map {

/** Base class for map field nodes. */
class Element final : public Node {
public:
    ~Element() final;

    auto key() const { return child<Expression>(0); }
    auto value() const { return child<Expression>(1); }

    static auto create(ASTContext* ctx, Expression* key, Expression* value, Meta meta = {}) {
        return ctx->make<Element>(ctx, {key, value}, std::move(meta));
    }

protected:
    Element(ASTContext* ctx, Nodes children, Meta meta = {})
        : Node(ctx, NodeTags, std::move(children), std::move(meta)) {}

    std::string _dump() const final;

    HILTI_NODE_0(ctor::map::Element, final);
};

using Elements = NodeVector<Element>;

} // namespace map

/** AST node for a `map` ctor. */
class Map : public Ctor {
public:
    auto value() const { return children<map::Element>(1, {}); }

    auto keyType() const {
        if ( auto* mtype = type()->type()->tryAs<type::Map>() )
            return mtype->keyType();
        else
            return type(); // auto
    }

    auto valueType() const {
        if ( auto* mtype = type()->type()->tryAs<type::Map>() )
            return mtype->valueType();
        else
            return type(); // auto
    }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, QualifiedType* type) { setChild(ctx, 0, type); }

    void setValue(ASTContext* ctx, const map::Elements& exprs) {
        removeChildren(1, {});
        addChildren(ctx, exprs);
    }

    static auto create(ASTContext* ctx, QualifiedType* key, QualifiedType* value, const map::Elements& elements,
                       Meta meta = {}) {
        auto* mtype = QualifiedType::create(ctx, type::Map::create(ctx, key, value, meta), Constness::Mutable, meta);
        return ctx->make<Map>(ctx, node::flatten(mtype, elements), std::move(meta));
    }

    static auto create(ASTContext* ctx, const map::Elements& elements, Meta meta = {}) {
        // bool is just an arbitrary place-holder type for empty values.
        auto* mtype = elements.empty() ?
                          QualifiedType::create(ctx, type::Bool::create(ctx, meta), Constness::Mutable, meta) :
                          QualifiedType::createAuto(ctx, meta);
        return ctx->make<Map>(ctx, node::flatten(mtype, elements), std::move(meta));
    }

protected:
    Map(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Map, Ctor, final);
};

} // namespace hilti::ctor
