// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

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

    auto expressions() const { return childsOfType<Expression>(); }
    auto items() const { return childsOfType<type::unit::Item>(); }
    auto itemNodes() { return nodesOfType<type::unit::Item>(); }

    /** Returns true if this is the default case. */
    bool isDefault() const { return expressions().empty() && ! _look_ahead; }

    /** Returns true if this is a look-ahead case. */
    bool isLookAhead() const { return _look_ahead; }

    auto properties() const { return node::Properties{{"default", isDefault()}, {"look-ahead", isLookAhead()}}; }

    bool operator==(const Case& other) const {
        return expressions() == other.expressions() && items() == other.items();
    }

private:
    bool _look_ahead = false;
};

inline Node to_node(Case c) { return Node(std::move(c)); }

} // namespace switch_

/** AST node for a unit field. */
class Switch : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Switch(std::optional<Expression> expr, const std::vector<switch_::Case>& cases, Engine e,
           std::optional<Expression> cond, std::vector<Hook> hooks, Meta m = Meta())
        : NodeBase(nodes(std::move(expr), std::move(cond), cases, std::move(hooks)), std::move(m)),
          _engine(e),
          _cases_start(2),
          _cases_end(_cases_start + static_cast<int>(cases.size())),
          _hooks_start(_cases_end),
          _hooks_end(-1) {}

    auto expression() const {
        return childs()[0].tryAs<Expression>();
        ;
    }
    Engine engine() const { return _engine; }
    auto condition() const { return childs()[1].tryAs<Expression>(); }
    auto cases() const { return childs<switch_::Case>(_cases_start, _cases_end); }
    auto cases() { return childs<switch_::Case>(_cases_start, _cases_end); }
    auto casesNodes() { return nodesOfType<switch_::Case>(); }

    auto hooks() const { return childs<Hook>(_hooks_start, _hooks_end); }

    /** Returns true if there's no field storing information. */
    bool hasNoFields() const;

    /**
     * Returns the case that an field is part of, if any.
     *
     * i: The field.
     */
    std::optional<switch_::Case> case_(const type::unit::item::Field& x);

    bool operator==(const Switch& other) const {
        return expression() == other.expression() && engine() == other.engine() && condition() == other.condition() &&
               cases() == other.cases() && hooks() == other.hooks();
    }

    // Unit item interface
    Type itemType() const { return type::Void(); }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{{"engine", to_string(_engine)}}; }

private:
    Engine _engine;
    const int _cases_start;
    const int _cases_end;
    const int _hooks_start;
    const int _hooks_end;
};

} // namespace spicy::type::unit::item
