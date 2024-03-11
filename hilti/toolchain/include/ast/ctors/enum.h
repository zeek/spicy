// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/enum.h>

namespace hilti::ctor {

/** AST node for a enum constructor. */
class Enum : public Ctor {
public:
    auto value() const { return child<type::enum_::Label>(0); }

    QualifiedType* type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, type::enum_::Label* label, const Meta& meta = {}) {
        return ctx->make<Enum>(ctx,
                               {label, QualifiedType::createExternal(ctx, label->enumType(), Constness::Const, meta)},
                               meta);
    }

protected:
    Enum(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Enum, Ctor, final);
};
} // namespace hilti::ctor
