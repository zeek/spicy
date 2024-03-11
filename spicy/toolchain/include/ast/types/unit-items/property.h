// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/void.h>

#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit sink.
 */
class Property : public unit::Item {
public:
    auto expression() const { return child<Expression>(0); }
    auto attributes() const { return child<AttributeSet>(1); }
    auto inherited() const { return _inherited; }

    QualifiedType* itemType() const final { return child<QualifiedType>(2); }

    bool isResolved(hilti::node::CycleDetector* cd) const final { return true; }

    std::string_view displayName() const final { return "unit property"; }

    static auto create(ASTContext* ctx, ID id, AttributeSet* attrs, bool inherited = false, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Property>(ctx, node::flatten(nullptr, attrs, hilti::type::Void::create(ctx)), std::move(id),
                                   false, std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, Expression* expr, AttributeSet* attrs, bool inherited = false,
                       Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Property>(ctx, node::flatten(expr, attrs, hilti::type::Void::create(ctx)), std::move(id),
                                   inherited, std::move(meta));
    }

protected:
    Property(ASTContext* ctx, Nodes children, ID id, bool inherited, Meta meta)
        : unit::Item(ctx, NodeTags, std::move(children), std::move(id), std::move(meta)), _inherited(inherited) {}

    SPICY_NODE_2(type::unit::item::Property, type::unit::Item, Declaration, final);

private:
    bool _inherited;
};

} // namespace spicy::type::unit::item
