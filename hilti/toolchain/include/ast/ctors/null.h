// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/null.h>

namespace hilti::ctor {

/** AST node for a `Null` ctor. */
class Null : public Ctor {
public:
    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        return std::shared_ptr<Null>(
            new Null(ctx, {QualifiedType::create(ctx, type::Null::create(ctx, meta), Constness::Const)}, meta));
    }

protected:
    Null(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Null)
};

} // namespace hilti::ctor
