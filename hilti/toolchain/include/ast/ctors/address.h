// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/rt/types/address.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/address.h>

namespace hilti::ctor {

/** AST node for a `address` ctor. */
class Address : public Ctor {
public:
    const auto& value() const { return _value; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", to_string(_value)}};
        return Ctor::properties() + p;
    }

    static auto create(ASTContext* ctx, hilti::rt::Address v, const Meta& meta = {}) {
        return ctx->make<Address>(ctx, {QualifiedType::create(ctx, type::Address::create(ctx, meta), Constness::Const)},
                                  v, meta);
    }

protected:
    Address(ASTContext* ctx, Nodes children, hilti::rt::Address v, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), _value(v) {}

    HILTI_NODE_1(ctor::Address, Ctor, final);

private:
    hilti::rt::Address _value;
};

} // namespace hilti::ctor
