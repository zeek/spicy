// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <string>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/type.h>
#include <hilti/base/util.h>

namespace hilti::type {

namespace tuple {

/** Base class for tuple element nodes. */
class Element final : public Node {
public:
    ~Element() final;

    const auto& id() const { return _id; }
    auto type() const { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}};
        return Node::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, QualifiedType* type, Meta meta = {}) {
        return ctx->make<Element>(ctx, {type}, std::move(id), std::move(meta));
    }

    static auto create(ASTContext* ctx, QualifiedType* type, Meta meta = {}) {
        return ctx->make<Element>(ctx, {type}, ID(), std::move(meta));
    }

protected:
    Element(ASTContext* ctx, Nodes children, ID id, Meta meta = {})
        : Node(ctx, NodeTags, std::move(children), std::move(meta)), _id(std::move(id)) {}

    HILTI_NODE_0(type::tuple::Element, final);

private:
    ID _id;
};

using Elements = NodeVector<Element>;

} // namespace tuple

/** AST node for a tuple type. */
class Tuple : public UnqualifiedType {
public:
    auto elements() const { return children<tuple::Element>(0, {}); }
    std::optional<std::pair<int, type::tuple::Element*>> elementByID(const ID& id) const;

    std::string_view typeClass() const final { return "tuple"; }

    bool isAllocable() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final;
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, const type::tuple::Elements& elements, Meta meta = {}) {
        return ctx->make<Tuple>(ctx, elements, std::move(meta));
    }

    static auto create(ASTContext* ctx, const QualifiedTypes& types, Meta meta = {}) {
        auto elements = util::transform(types, [&](const auto& t) { return tuple::Element::create(ctx, t, meta); });
        return ctx->make<Tuple>(ctx, std::move(elements), std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Tuple>(ctx, Wildcard(), m);
    }

protected:
    Tuple(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Tuple(ASTContext* ctx, Wildcard _, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"tuple(*)"}, std::move(meta)) {}


    HILTI_NODE_1(type::Tuple, UnqualifiedType, final);
};

} // namespace hilti::type
