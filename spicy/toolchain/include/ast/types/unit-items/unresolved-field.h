// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <utility>
#include <vector>

#include <hilti/ast/types/unknown.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/engine.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit field with its type determined by a not yet resolved
 * ID. The ID may refer to either a type or an ctor.
 */
class UnresolvedField : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    UnresolvedField(const std::optional<ID>& id, Type type, Engine e, bool skip, const std::vector<Expression>& args,
                    std::optional<Expression> repeat, const std::vector<Expression>& sinks,
                    std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {},
                    std::vector<Hook> hooks = {}, Meta m = Meta())

        : NodeBase(nodes(node::none, std::move(type), id, std::move(repeat), std::move(attrs), std::move(cond), args,
                         sinks, std::move(hooks)),
                   std::move(m)),
          _is_skip(skip),
          _engine(e),
          _args_start(6),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())) {}

    UnresolvedField(const std::optional<ID>& id, Ctor ctor, Engine e, bool skip, const std::vector<Expression>& args,
                    std::optional<Expression> repeat, const std::vector<Expression>& sinks,
                    std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {},
                    std::vector<Hook> hooks = {}, Meta m = Meta())
        : NodeBase(nodes(node::none, std::move(ctor), id, std::move(repeat), std::move(attrs), std::move(cond), args,
                         sinks, std::move(hooks)),
                   std::move(m)),
          _is_skip(skip),
          _engine(e),
          _args_start(6),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())) {}

    UnresolvedField(const std::optional<ID>& id, Item item, Engine e, bool skip, const std::vector<Expression>& args,
                    std::optional<Expression> repeat, const std::vector<Expression>& sinks,
                    std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {},
                    std::vector<Hook> hooks = {}, Meta m = Meta())
        : NodeBase(nodes(node::none, std::move(item), id, std::move(repeat), std::move(attrs), std::move(cond), args,
                         sinks, std::move(hooks)),
                   std::move(m)),
          _is_skip(skip),
          _engine(e),
          _args_start(6),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())) {}

    UnresolvedField(std::optional<ID> id, ID unresolved_id, Engine e, bool skip, const std::vector<Expression>& args,
                    std::optional<Expression> repeat, const std::vector<Expression>& sinks,
                    std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {},
                    std::vector<Hook> hooks = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(unresolved_id), node::none, std::move(id), std::move(repeat), std::move(attrs),
                         std::move(cond), args, sinks, std::move(hooks)),
                   std::move(m)),
          _is_skip(skip),
          _engine(e),
          _args_start(6),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())) {}

    auto fieldID() const { return children()[2].tryAs<ID>(); }
    auto unresolvedID() const { return children()[0].tryAs<ID>(); }
    const auto& index() const { return _index; }

    // Only one of these will have return value.
    auto ctor() const { return children()[1].tryAs<Ctor>(); }
    auto item() const { return children()[1].tryAs<Item>(); }
    auto type() const { return children()[1].tryAs<Type>(); }

    auto repeatCount() const { return children()[3].tryAs<Expression>(); }
    auto attributes() const { return children()[4].tryAs<AttributeSet>(); }
    auto condition() const { return children()[5].tryAs<Expression>(); }
    auto arguments() const { return children<Expression>(_args_start, _args_end); }
    auto sinks() const { return children<Expression>(_sinks_start, _sinks_end); }
    auto hooks() const { return children<Hook>(_sinks_end, -1); }
    auto isSkip() const { return _is_skip; }
    Engine engine() const { return _engine; }

    void setIndex(uint64_t index) { _index = index; }
    void setSkip(bool skip) { _is_skip = skip; }
    void setType(const Type& t) { children()[1] = t; }

    bool operator==(const UnresolvedField& other) const {
        return _is_skip == other._is_skip && _engine == other._engine && unresolvedID() == other.unresolvedID() &&
               fieldID() == other.fieldID() && attributes() == other.attributes() && arguments() == other.arguments() &&
               sinks() == other.sinks() && condition() == other.condition() && hooks() == other.hooks();
    }

    // Unit item interface
    const Type& itemType() const { return hilti::type::auto_; }
    bool isResolved() const { return false; }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{{"engine", to_string(_engine)}}; }

private:
    bool _is_skip;
    Engine _engine;
    std::optional<uint64_t> _index;
    const int _args_start;
    const int _args_end;
    const int _sinks_start;
    const int _sinks_end;
};

} // namespace spicy::type::unit::item
