// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/real.h>

namespace hilti::ctor {

/** AST node for a `real` ctor. */
class Real : public Ctor {
public:
    const auto& value() const { return _value; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", _value}};
        return Ctor::properties() + p;
    }

    static auto create(ASTContext* ctx, double v, const Meta& meta = {}) {
        return ctx->make<Real>(ctx, {QualifiedType::create(ctx, type::Real::create(ctx, meta), Constness::Const)}, v,
                               meta);
    }

protected:
    Real(ASTContext* ctx, Nodes children, double v, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), _value(v) {}

    HILTI_NODE_1(ctor::Real, Ctor, final);

private:
    double _value;
};

} // namespace hilti::ctor
