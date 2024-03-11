// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/integer.h>

namespace hilti::ctor {

namespace detail {
/** Base class for AST nodes for both signed and unsigned integer constructors. */
template<typename Value>
class IntegerBase : public Ctor {
public:
    const auto& value() const { return _value; }
    auto width() const { return _width; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", _value}, {"width", _width}};
        return Ctor::properties() + p;
    }

protected:
    IntegerBase(ASTContext* ctx, node::Tags node_tags, Nodes children, Value v, unsigned int width, Meta meta)
        : Ctor(ctx, node_tags, std::move(children), std::move(meta)), _value(v), _width(width) {}

private:
    Value _value;
    unsigned int _width;
};

} // namespace detail

/** AST node for a signed integer constructor. */
class SignedInteger : public detail::IntegerBase<int64_t> {
public:
    static auto create(ASTContext* ctx, int64_t value, unsigned int width, const Meta& meta = {}) {
        return ctx->make<SignedInteger>(ctx,
                                        {QualifiedType::create(ctx, type::SignedInteger::create(ctx, width, meta),
                                                               Constness::Const)},
                                        value, width, meta);
    }

protected:
    SignedInteger(ASTContext* ctx, Nodes children, int64_t value, unsigned int width, Meta meta)
        : IntegerBase(ctx, NodeTags, std::move(children), value, width, std::move(meta)) {}

    HILTI_NODE_1(ctor::SignedInteger, Ctor, final);
};

/** AST node for a unsigned integer constructor. */
class UnsignedInteger : public detail::IntegerBase<uint64_t> {
public:
    static auto create(ASTContext* ctx, uint64_t value, unsigned int width, const Meta& meta = {}) {
        return ctx->make<UnsignedInteger>(ctx,
                                          {QualifiedType::create(ctx, type::UnsignedInteger::create(ctx, width, meta),
                                                                 Constness::Const)},
                                          value, width, meta);
    }

    static auto create(ASTContext* ctx, uint64_t value, unsigned int width, UnqualifiedType* t, Meta meta = {}) {
        return ctx->make<UnsignedInteger>(ctx, {QualifiedType::create(ctx, t, Constness::Const)}, value, width,
                                          std::move(meta));
    }

protected:
    UnsignedInteger(ASTContext* ctx, Nodes children, uint64_t value, unsigned int width, Meta meta)
        : IntegerBase(ctx, NodeTags, std::move(children), value, width, std::move(meta)) {}

    HILTI_NODE_1(ctor::UnsignedInteger, Ctor, final);
};

} // namespace hilti::ctor
