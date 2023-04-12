// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/types/vector.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/engine.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>

namespace spicy::type::unit::item {

namespace switch_ {

/** AST node for a unit switch's case. */
class Case : public hilti::NodeBase {
public:
    Case(std::vector<Expression> exprs, std::vector<type::unit::Item> items, Meta m = Meta())
        : NodeBase(hilti::nodes(std::move(items), std::move(exprs)), std::move(m)) {}

    /** Constructor for a default case. */
    Case(std::vector<type::unit::Item> items, Meta m = Meta())
        : NodeBase(hilti::nodes(std::move(items)), std::move(m)) {}

    /** Constructor for look-ahead case. */
    Case(type::unit::Item field, Meta m = Meta())
        : NodeBase(hilti::nodes(std::move(field)), std::move(m)), _look_ahead(true) {}

    Case() = default;

    auto expressions() const { return childrenOfType<Expression>(); }
    auto items() const { return childrenOfType<type::unit::Item>(); }
    auto itemRefs() const { return childRefsOfType<type::unit::Item>(); }

    /** Returns true if this is the default case. */
    bool isDefault() const { return expressions().empty() && ! _look_ahead; }

    /** Returns true if this is a look-ahead case. */
    bool isLookAhead() const { return _look_ahead; }

    /** Returns true if all items have been resolved. */
    bool isResolved() const {
        for ( const auto& i : items() ) {
            if ( ! i.isResolved() )
                return false;
        }

        return true;
    }

    auto properties() const { return node::Properties{{"default", isDefault()}, {"look-ahead", isLookAhead()}}; }

    bool operator==(const Case& other) const;

private:
    bool _look_ahead = false;
};

inline Node to_node(Case c) { return Node(std::move(c)); }

} // namespace switch_

/** AST node for a unit field. */
class Switch : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Switch(std::optional<Expression> expr, const std::vector<switch_::Case>& cases, Engine e,
           std::optional<Expression> cond, std::vector<Hook> hooks, std::optional<AttributeSet> attributes,
           Meta m = Meta())
        : NodeBase(nodes(std::move(expr), std::move(cond), std::move(attributes), cases, std::move(hooks)),
                   std::move(m)),
          _engine(e) {}

    Engine engine() const { return _engine; }
    auto attributes() const { return children()[2].tryAs<AttributeSet>(); }
    auto cases() const { return childrenOfType<switch_::Case>(); }
    auto condition() const { return children()[1].tryAs<Expression>(); }
    auto expression() const { return children()[0].tryAs<Expression>(); }
    auto hooks() const { return childrenOfType<Hook>(); }

    auto itemRefs() const { return childRefsOfType<type::unit::Item>(); }

    /** Returns true if there's no field storing information. */
    bool hasNoFields() const;

    /**
     * Returns the case that an field is part of, if any.
     *
     * i: The field.
     */
    hilti::optional_ref<const switch_::Case> case_(const type::unit::item::Field& x);

    bool operator==(const Switch& other) const {
        return expression() == other.expression() && engine() == other.engine() && condition() == other.condition() &&
               cases() == other.cases() && hooks() == other.hooks();
    }

    // Unit item interface
    const Type& itemType() const { return type::void_; }

    bool isResolved() const {
        for ( const auto& c : cases() ) {
            if ( ! c.isResolved() )
                return false;
        }

        return true;
    }

    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{{"engine", to_string(_engine)}}; }

private:
    Engine _engine;
};

} // namespace spicy::type::unit::item
