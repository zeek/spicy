// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

#include <spicy/ast/attribute.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit variable.
 *
 * @note We don't support hooks for variables because we can't reliably
 * identify assignments in the generated code. To do that, we'd need to trap
 * struct field assignments at the C++ level.
 */
class Variable : public unit::Item {
public:
    auto default_() const { return child<Expression>(1); }
    auto attributes() const { return child<AttributeSet>(2); }

    bool isOptional() const { return attributes()->find(attribute::kind::Optional); }

    QualifiedType* itemType() const final { return child<QualifiedType>(0); }

    bool isResolved(hilti::node::CycleDetector* cd) const final { return itemType()->isResolved(cd); }

    std::string_view displayName() const final { return "unit variable"; }

    static auto create(ASTContext* ctx, ID id, QualifiedType* type, Expression* default_, AttributeSet* attrs,
                       Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Variable>(ctx, {type, default_, attrs}, std::move(id), std::move(meta));
    }

protected:
    Variable(ASTContext* ctx, Nodes children, ID id, Meta meta)
        : unit::Item(ctx, NodeTags, std::move(children), std::move(id), std::move(meta)) {}

    SPICY_NODE_2(type::unit::item::Variable, type::unit::Item, Declaration, final);
};

} // namespace spicy::type::unit::item
