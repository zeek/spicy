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

#include <spicy/ast/engine.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>

namespace spicy::type::unit::item {

namespace switch_ {

/** AST node for a unit switch's case. */
class Case : public Node {
public:
    ~Case() override;

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
        return std::shared_ptr<Case>(new Case(ctx, node::flatten(exprs, items), false, m));
    }

    /** Factory function for a default case. */
    static auto create(ASTContext* ctx, const type::unit::Items& items, const Meta& m = Meta()) {
        return std::shared_ptr<Case>(new Case(ctx, items, false, m));
    }

    /** Factory function for a look-ahead case. */
    static auto create(ASTContext* ctx, const type::unit::ItemPtr& field, const Meta& m = Meta()) {
        return std::shared_ptr<Case>(new Case(ctx, {field}, true, m));
    }

protected:
    Case(ASTContext* ctx, Nodes children, bool look_ahead, Meta meta)
        : Node::Node(ctx, std::move(children), std::move(meta)), _look_ahead(look_ahead) {}

    HILTI_NODE(spicy, Case);

private:
    bool _look_ahead = false;
};

using CasePtr = std::shared_ptr<Case>;
using Cases = std::vector<CasePtr>;

} // namespace switch_

class Switch : public unit::Item {
public:
    Engine engine() const { return _engine; }
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
    switch_::CasePtr case_(const type::unit::item::FieldPtr& field) const;

    QualifiedTypePtr itemType() const final { return child<QualifiedType>(3); }

    bool isResolved(hilti::node::CycleDetector* cd) const final {
        for ( const auto& c : cases() ) {
            if ( ! c->isResolved(cd) )
                return false;
        }

        return true;
    }

    std::string displayName() const final { return "unit switch"; }

    node::Properties properties() const final {
        auto p = node::Properties{{"engine", to_string(_engine)}};
        return unit::Item::properties() + p;
    }

    static auto create(ASTContext* ctx, ExpressionPtr expr, type::unit::item::switch_::Cases cases, Engine engine,
                       ExpressionPtr cond, spicy::declaration::Hooks hooks, AttributeSetPtr attrs,
                       const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return std::shared_ptr<Switch>(
            new Switch(ctx,
                       node::flatten(std::move(expr), std::move(cond), attrs,
                                     QualifiedType::create(ctx, hilti::type::Void::create(ctx),
                                                           hilti::Constness::Const),
                                     std::move(cases), std::move(hooks)),
                       engine, meta));
    }

protected:
    Switch(ASTContext* ctx, Nodes children, Engine engine, const Meta& meta)
        : unit::Item(ctx, std::move(children), ID(), meta), _engine(engine) {}

    HILTI_NODE(spicy, Switch)

private:
    Engine _engine;
};

} // namespace spicy::type::unit::item
