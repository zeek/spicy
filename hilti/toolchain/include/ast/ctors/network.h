// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/types/network.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/network.h>

namespace hilti::ctor {

/** AST node for a `network` ctor. */
class Network : public Ctor {
public:
    const auto& value() const { return _value; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", to_string(_value)}};
        return Ctor::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, hilti::rt::Network v, const Meta& meta = {}) {
        return ctx->make<Network>(ctx, {QualifiedType::create(ctx, type::Network::create(ctx, meta), Constness::Const)},
                                  v, meta);
    }

protected:
    Network(ASTContext* ctx, Nodes children, hilti::rt::Network v, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), _value(v) {}

    HILTI_NODE_1(ctor::Network, Ctor, final);

private:
    hilti::rt::Network _value;
};

} // namespace hilti::ctor
