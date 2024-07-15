// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/void.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>

namespace spicy::type::unit::item {

namespace switch_ {

/** AST node for a unit switch's case. */
class Case : public Node {
public:
    auto expressions() const { return childrenOfType<Expression>(); }
    auto items() const { return childrenOfType<type::unit::Item>(); }

    /** Returns true if this is the default case. */
    bool isDefault() const { return expressions().empty() && ! _look_ahead; }

    /** Returns true if this is a look-ahead case. */
    bool isLookAhead() const { return _look_ahead; }

    /** Returns true if all items have been resolved. */
    bool isResolved(hilti::node::CycleDetector* cd = nullptr) const {
        for ( const auto& i : items() ) {
            if ( ! i->isResolved(cd) )
                return false;
        }

        return true;
    }

    node::Properties properties() const final {
        auto p = node::Properties{{"look-ahead", _look_ahead}, {"default", isDefault()}};
        return Node::properties() + p;
    }

    static auto create(ASTContext* ctx, const Expressions& exprs, const type::unit::Items& items,
                       const Meta& m = Meta()) {
        return ctx->make<Case>(ctx, node::flatten(exprs, items), false, m);
    }

    /** Factory function for a default case. */
    static auto create(ASTContext* ctx, const type::unit::Items& items, const Meta& m = Meta()) {
        return ctx->make<Case>(ctx, items, false, m);
    }

    /** Factory function for a look-ahead case. */
    static auto create(ASTContext* ctx, type::unit::Item* field, const Meta& m = Meta()) {
        return ctx->make<Case>(ctx, {field}, true, m);
    }

protected:
    Case(ASTContext* ctx, Nodes children, bool look_ahead, Meta meta)
        : Node::Node(ctx, NodeTags, std::move(children), std::move(meta)), _look_ahead(look_ahead) {}

    SPICY_NODE_0(type::unit::item::switch_::Case, final);

private:
    bool _look_ahead = false;
};

using Cases = NodeVector<Case>;

} // namespace switch_

class Switch : public unit::Item {
public:
    auto expression() const { return child<Expression>(0); }
    auto condition() const { return child<Expression>(1); }
    auto attributes() const { return child<AttributeSet>(2); }
    auto cases() const { return childrenOfType<switch_::Case>(); }
    auto hooks() const { return childrenOfType<declaration::Hook>(); }

    /** Returns true if there's no field storing information. */
    bool hasNoFields() const;

    /**
     * Returns the case that an field is part of, if any.
     *
     * field: The field.
     */
    switch_::Case* case_(const type::unit::item::Field* field) const;

    QualifiedType* itemType() const final { return child<QualifiedType>(3); }

    bool isResolved(hilti::node::CycleDetector* cd) const final {
        for ( const auto& c : cases() ) {
            if ( ! c->isResolved(cd) )
                return false;
        }

        return true;
    }

    std::string_view displayName() const final { return "unit switch"; }

    static auto create(ASTContext* ctx, Expression* expr, type::unit::item::switch_::Cases cases, Expression* cond,
                       spicy::declaration::Hooks hooks, AttributeSet* attrs, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Switch>(ctx,
                                 node::flatten(expr, cond, attrs,
                                               QualifiedType::create(ctx, hilti::type::Void::create(ctx),
                                                                     hilti::Constness::Const),
                                               std::move(cases), std::move(hooks)),
                                 std::move(meta));
    }

protected:
    Switch(ASTContext* ctx, Nodes children, Meta meta)
        : unit::Item(ctx, NodeTags, std::move(children), ID(), std::move(meta)) {}

    SPICY_NODE_2(type::unit::item::Switch, type::unit::Item, Declaration, final);
};

} // namespace spicy::type::unit::item
