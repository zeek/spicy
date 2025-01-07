// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/types/interval.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/interval.h>

namespace hilti::ctor {

/** AST node for a `interval` ctor. */
class Interval : public Ctor {
public:
    const auto& value() const { return _value; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", to_string(_value)}};
        return Ctor::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, hilti::rt::Interval v, const Meta& meta = {}) {
        return ctx->make<Interval>(ctx,
                                   {QualifiedType::create(ctx, type::Interval::create(ctx, meta), Constness::Const)}, v,
                                   meta);
    }

protected:
    Interval(ASTContext* ctx, Nodes children, hilti::rt::Interval v, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), _value(v) {}

    HILTI_NODE_1(ctor::Interval, Ctor, final);

private:
    hilti::rt::Interval _value;
};

} // namespace hilti::ctor
