// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <utility>
#include <vector>

#include <hilti/ast/types/vector.h>
#include <hilti/base/uniquer.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/engine.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/** AST node for a unit field. */
class Field : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Field(const std::optional<ID>& id, Type type, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          Meta m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), std::move(type), node::none, repeat, std::move(attrs),
                         std::move(cond), args, sinks, hooks),
                   std::move(m)),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(6),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field(const std::optional<ID>& id, Ctor ctor, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          Meta m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), ctor.type(), ctor, repeat, std::move(attrs), std::move(cond),
                         args, sinks, hooks),
                   std::move(m)),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(6),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field(const std::optional<ID>& id, Item item, Engine e, const std::vector<Expression>& args,
          std::optional<Expression> repeat, const std::vector<Expression>& sinks,
          std::optional<AttributeSet> attrs = {}, std::optional<Expression> cond = {}, std::vector<Hook> hooks = {},
          const Meta& m = Meta())
        : NodeBase(nodes((id ? id : _uniquer.get("anon")), item.itemType(), item, repeat, std::move(attrs),
                         std::move(cond), args, sinks, hooks),
                   m),
          _is_forwarding(false),
          _is_transient(! id.has_value()),
          _engine(e),
          _args_start(6),
          _args_end(_args_start + static_cast<int>(args.size())),
          _sinks_start(_args_end),
          _sinks_end(_sinks_start + static_cast<int>(sinks.size())),
          _hooks_start(_sinks_end),
          _hooks_end(_hooks_start + static_cast<int>(hooks.size())) {}

    Field() = delete;
    Field(const Field& other) = default;
    Field(Field&& other) = default;
    ~Field() = default;

    const auto& id() const { return childs()[0].as<ID>(); }
    auto index() const { return _index; }
    auto ctor() const { return childs()[2].tryReferenceAs<Ctor>(); }
    auto item() const { return childs()[2].tryReferenceAs<Item>(); }

    auto repeatCount() const { return childs()[3].tryReferenceAs<Expression>(); }
    auto attributes() const { return childs()[4].tryReferenceAs<AttributeSet>(); }
    auto condition() const { return childs()[5].tryReferenceAs<Expression>(); }
    auto arguments() const { return childs<Expression>(_args_start, _args_end); }
    auto sinks() const { return childs<Expression>(_sinks_start, _sinks_end); }
    auto hooks() const { return childs<Hook>(_hooks_start, _hooks_end); }
    Engine engine() const { return _engine; }

    bool isContainer() const { return repeatCount().has_value(); }
    bool isForwarding() const { return _is_forwarding; }
    bool isTransient() const { return _is_transient; }
    bool emitHook() const { return ! isTransient() || hooks().size(); }

    Type parseType() const;

    Type originalType() const { return childs()[1].as<Type>(); }

    Node& originalTypeNode() { return childs()[1]; }
    Node& ctorNode() { return childs()[2]; }
    Node& itemNode() { return childs()[2]; }
    Node& attributesNode() { return childs()[4]; }

    // Get the `&convert` expression, if any.
    //
    // For unit-level converts, returns the unit type as well.
    std::optional<std::pair<Expression, std::optional<Type>>> convertExpression() const;

    bool operator==(const Field& other) const {
        return _engine == other._engine && id() == other.id() && originalType() == other.originalType() &&
               attributes() == other.attributes() && arguments() == other.arguments() && sinks() == other.sinks() &&
               condition() == other.condition() && hooks() == other.hooks(); // TODO
    }

    Field& operator=(const Field& other) = default;
    Field& operator=(Field&& other) = default;

    // Unit item interface
    Type itemType() const;
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const {
        return node::Properties{{"engine", to_string(_engine)},
                                {"transient", _is_transient},
                                {"forwarding", _is_forwarding}};
    }

    // Helper function for vector fields that returns the type of the
    // vector's elements. The helper can be used in situations where the
    // field type might not be fully resolved. It computes the type
    // indirectly and dynamically: It looks up the struct that `self` is
    // currently pointing to, and then extracts the auxiliary type from the
    // struct's field named *id*. That type must be a vector, from which it
    // then retrieves the element type.
    //
    // This is rather specialized of course, but necessary in some contexts.
    // Note that it can only be used (1) at code locations where ``self``
    // evaluates to the desired struct, and (2) the field's auxiliary type
    // has been set to a vector type (as we do for structs corresponding to
    // units, where the auxiliary type is the parse type of the field).
    static Type vectorElementTypeThroughSelf(ID id);

    /**
     * Copies an existing field but changes its unit index.
     *
     * @param unit original field
     * @param index the new index of the field
     * @return new Field with unit index set as requested
     */
    static Field setIndex(const Field& f, uint64_t index) {
        auto x = Item(f)._clone().as<Field>();
        x._index = index;
        return x;
    }

    static Field setForwarding(const Field& f, bool is_forwarding) {
        auto x = Item(f)._clone().as<Field>();
        x._is_forwarding = is_forwarding;
        return x;
    }

private:
    std::optional<uint64_t> _index;
    bool _is_forwarding;
    bool _is_transient;
    Engine _engine;
    int _args_start;
    int _args_end;
    int _sinks_start;
    int _sinks_end;
    int _hooks_start;
    int _hooks_end;

    static inline hilti::util::Uniquer<ID> _uniquer;
};

} // namespace spicy::type::unit::item
