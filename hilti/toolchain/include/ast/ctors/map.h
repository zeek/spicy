// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

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

    static auto create(ASTContext* ctx, const ExpressionPtr& key, const ExpressionPtr& value, Meta meta = {}) {
        return std::shared_ptr<Element>(new Element(ctx, {key, value}, std::move(meta)));
    }

protected:
    Element(ASTContext* ctx, Nodes children, Meta meta = {})
        : Node(ctx, NodeTags, std::move(children), std::move(meta)) {}

    std::string _dump() const final;

    HILTI_NODE_0(ctor::map::Element, final);
};

using ElementPtr = std::shared_ptr<Element>;
using Elements = std::vector<ElementPtr>;

} // namespace map

/** AST node for a `map` ctor. */
class Map : public Ctor {
public:
    auto value() const { return children<map::Element>(1, {}); }

    auto keyType() const {
        if ( auto mtype = type()->type()->tryAs<type::Map>() )
            return mtype->keyType();
        else
            return type(); // auto
    }

    auto valueType() const {
        if ( auto mtype = type()->type()->tryAs<type::Map>() )
            return mtype->valueType();
        else
            return type(); // auto
    }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, const QualifiedTypePtr& type) { setChild(ctx, 0, type); }

    void setValue(ASTContext* ctx, map::Elements exprs) {
        removeChildren(1, {});
        addChildren(ctx, std::move(exprs));
    }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& key, const QualifiedTypePtr& value,
                       map::Elements elements, const Meta& meta = {}) {
        auto mtype = QualifiedType::create(ctx, type::Map::create(ctx, key, value, meta), Constness::Mutable, meta);
        return std::shared_ptr<Map>(new Map(ctx, node::flatten(mtype, std::move(elements)), meta));
    }

    static auto create(ASTContext* ctx, map::Elements elements, const Meta& meta = {}) {
        // bool is just an arbitrary place-holder type for empty values.
        auto mtype = elements.empty() ?
                         QualifiedType::create(ctx, type::Bool::create(ctx, meta), Constness::Mutable, meta) :
                         QualifiedType::createAuto(ctx, meta);
        return std::shared_ptr<Map>(new Map(ctx, node::flatten(mtype, std::move(elements)), meta));
    }

protected:
    Map(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Map, Ctor, final);
};

} // namespace hilti::ctor
