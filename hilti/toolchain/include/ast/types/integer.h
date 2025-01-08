// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

namespace detail {

/** Common base class for an AST node representing an integer type. */
class IntegerBase : public UnqualifiedType {
public:
    auto width() const { return _width; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    node::Properties properties() const final {
        auto p = node::Properties{{"width", _width}};
        return UnqualifiedType::properties() + std::move(p);
    }

protected:
    IntegerBase(ASTContext* ctx, node::Tags node_tags, type::Unification u, Nodes children, unsigned int width,
                const Meta& m = Meta())
        : UnqualifiedType(ctx, node_tags, std::move(u), std::move(children), m), _width(width) {}
    IntegerBase(ASTContext* ctx, node::Tags node_tags, Wildcard _, type::Unification u, const Meta& m = Meta())
        : UnqualifiedType(ctx, node_tags, Wildcard(), std::move(u), m) {}

private:
    unsigned int _width = 0;
};

} // namespace detail

/** AST node for a signed integer type. */
class SignedInteger : public detail::IntegerBase {
public:
    std::string_view typeClass() const final { return "int"; }

    static SignedInteger* create(ASTContext* ctx, unsigned int width, const Meta& m = Meta());

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<SignedInteger>(ctx, Wildcard(), m);
    }

protected:
    SignedInteger(ASTContext* ctx, const Nodes& children, unsigned int width, const Meta& m = Meta())
        : IntegerBase(ctx, NodeTags, {util::fmt("int%" PRIu64, width)}, children, width, m) {}
    SignedInteger(ASTContext* ctx, Wildcard _, const Meta& m = Meta())
        : IntegerBase(ctx, NodeTags, Wildcard(), {"int<*>"}, m) {}

    HILTI_NODE_1(type::SignedInteger, UnqualifiedType, final);
};

/** AST node for an unsigned integer type. */
class UnsignedInteger : public detail::IntegerBase {
public:
    std::string_view typeClass() const final { return "uint"; }

    static UnsignedInteger* create(ASTContext* ctx, unsigned int width, const Meta& m = Meta());

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<UnsignedInteger>(ctx, Wildcard(), m);
    }

protected:
    UnsignedInteger(ASTContext* ctx, const Nodes& children, unsigned int width, const Meta& m = Meta())
        : IntegerBase(ctx, NodeTags, {util::fmt("uint%" PRIu64, width)}, children, width, m) {}
    UnsignedInteger(ASTContext* ctx, Wildcard _, const Meta& m = Meta())
        : IntegerBase(ctx, NodeTags, Wildcard(), {"uint<*>"}, m) {}

    HILTI_NODE_1(type::UnsignedInteger, UnqualifiedType, final);
};

} // namespace hilti::type
