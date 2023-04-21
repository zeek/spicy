// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/types/void.h>
#include <hilti/base/uniquer.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/** * AST node for a `skip` item. */
class Skip : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Skip(const std::optional<ID>& id, std::optional<AttributeSet> attrs = {},
         std::optional<hilti::Expression> condition = {}, std::vector<Hook> hooks = {}, Meta m = Meta())
        : NodeBase(nodes(id ? id : _uniquer.get("skip"), attrs ? std::move(attrs) : AttributeSet(),
                         std::move(condition), std::move(hooks)),
                   std::move(m)),
          _is_anonymous(! id) {}

    auto id() const { return child<ID>(0); }
    const auto& attributes() const { return child<AttributeSet>(1); }
    auto condition() const { return children()[2].tryAs<Expression>(); }
    auto hooks() const { return children<Hook>(3, -1); }

    bool isAnonymous() const { return _is_anonymous; }
    bool emitHook() const { return ! isAnonymous() || hooks().size(); }

    bool operator==(const Skip& other) const {
        return id() == other.id() && attributes() == other.attributes() && condition() == other.condition();
    }

    // Unit item interface
    const Type& itemType() const { return type::void_; }
    bool isResolved() const { return true; }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{{"anonymous", _is_anonymous}}; }

private:
    bool _is_anonymous;

    static inline hilti::util::Uniquer<ID> _uniquer;
};

} // namespace spicy::type::unit::item
