// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>

namespace hilti::ctor {

/** AST node for a constructor that's been coerced from one type to another. */
class Coerced : public Ctor {
public:
    auto originalCtor() const { return child<Ctor>(0); }
    auto coercedCtor() const { return child<Ctor>(1); }

    QualifiedTypePtr type() const final { return coercedCtor()->type(); }

    static auto create(ASTContext* ctx, const CtorPtr& orig, const CtorPtr& new_, const Meta& meta = {}) {
        return std::shared_ptr<Coerced>(new Coerced(ctx, {orig, new_}, meta));
    }

protected:
    Coerced(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Coerced)
};

} // namespace hilti::ctor
