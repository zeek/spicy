// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for a constructor expression. */
class Ctor : public Expression {
public:
    auto ctor() const { return child<hilti::Ctor>(0); }

    QualifiedTypePtr type() const final { return ctor()->type(); }

    static auto create(ASTContext* ctx, const CtorPtr& ctor, const Meta& meta = {}) {
        assert(ctor->isA<hilti::Ctor>());
        return std::shared_ptr<Ctor>(new Ctor(ctx, {ctor}, meta));
    }

protected:
    Ctor(ASTContext* ctx, Nodes children, Meta meta) : Expression(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Ctor)
};

} // namespace hilti::expression
