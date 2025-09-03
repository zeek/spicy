// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/void.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/** AST node for a unit block containing subitems, optionally guarded by a boolean expression. */
class Block : public unit::Item {
public:
    auto condition() const { return child<Expression>(1); }
    auto attributes() const { return child<AttributeSet>(2); }
    auto items() const { return children<type::unit::Item>(3, _else_start); }
    auto elseItems() const { return children<type::unit::Item>(_else_start, {}); }
    auto allItems() const { return children<type::unit::Item>(3, {}); }

    void setCondition(ASTContext* ctx, Expression* c) { setChild(ctx, 1, c); }

    QualifiedType* itemType() const final { return child<QualifiedType>(0); }

    bool isResolved(hilti::node::CycleDetector* cd = nullptr) const final {
        for ( const auto& i : allItems() ) {
            if ( ! i->isResolved(cd) )
                return false;
        }

        return true;
    }

    std::string_view displayName() const final { return "unit block"; }

    static auto create(ASTContext* ctx, const type::unit::Items& items, Expression* condition = nullptr,
                       const type::unit::Items& else_items = {}, AttributeSet* attrs = nullptr,
                       const Meta& m = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Block>(ctx, items.size() + 3, node::flatten(condition, attrs, items, else_items), m);
    }

protected:
    Block(ASTContext* ctx, int else_start, const Nodes& children, Meta meta)
        : unit::Item(ctx, NodeTags,
                     node::flatten(QualifiedType::create(ctx, hilti::type::Void::create(ctx), hilti::Constness::Const),
                                   children),
                     ID(), std::move(meta)),
          _else_start(else_start) {}

    SPICY_NODE_2(type::unit::item::Block, type::unit::Item, Declaration, final);

private:
    int _else_start;
};

} // namespace spicy::type::unit::item
