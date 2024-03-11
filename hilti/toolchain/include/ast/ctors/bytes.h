// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/bytes.h>

namespace hilti::ctor {

/** AST node for a `bytes` ctor. */
class Bytes : public Ctor {
public:
    const auto& value() const { return _value; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", _value}};
        return Ctor::properties() + p;
    }

    static auto create(ASTContext* ctx, std::string value, const Meta& meta = {}) {
        return ctx->make<Bytes>(ctx, {QualifiedType::create(ctx, type::Bytes::create(ctx, meta), Constness::Const)},
                                std::move(value), meta);
    }

protected:
    Bytes(ASTContext* ctx, Nodes children, std::string value, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), _value(std::move(value)) {}

    HILTI_NODE_1(ctor::Bytes, Ctor, final);

private:
    std::string _value;
};

} // namespace hilti::ctor
