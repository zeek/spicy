// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/function.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/engine.h>

namespace spicy {

namespace type {

class Unit;

namespace unit::item {
class Field;
}

} // namespace type

/** AST node representing a Spicy unit hook. */
class Hook : public hilti::NodeBase {
public:
    Hook(const std::vector<type::function::Parameter>& params, std::optional<Statement> body, Engine engine,
         std::optional<AttributeSet> attrs = {}, const Meta& m = Meta())
        : NodeBase(nodes(Function(ID(),
                                  type::Function(type::function::Result(type::void_, m), params,
                                                 type::function::Flavor::Hook, m),
                                  std::move(body), hilti::function::CallingConvention::Standard, std::move(attrs), m),
                         hilti::node::none),
                   m),
          _engine(engine) {}

    Hook() = default;

    const auto& function() const { return child<Function>(0); }

    auto body() const { return function().body(); }
    const auto& ftype() const { return function().ftype(); }
    const auto& id() const { return function().id(); }
    const auto& type() const { return function().type(); }

    Engine engine() const { return _engine; }
    NodeRef ddRef() const;
    hilti::optional_ref<const spicy::type::Unit> unitType() const;
    hilti::optional_ref<const spicy::type::unit::item::Field> unitField() const;
    std::optional<Expression> priority() const;

    bool isForEach() const { return AttributeSet::find(function().attributes(), "foreach").has_value(); }
    bool isDebug() const { return AttributeSet::find(function().attributes(), "%debug").has_value(); }

    void setID(const ID& id) { children()[0].as<Function>().setID(id); }
    void setUnitTypeRef(NodeRef p) { _unit_type = std::move(p); }
    void setFieldRef(NodeRef p) { _unit_field = std::move(p); }
    void setDDType(Type t) { children()[1] = hilti::expression::Keyword::createDollarDollarDeclaration(std::move(t)); }
    void setParameters(const std::vector<type::function::Parameter>& params) {
        children()[0].as<Function>().setFunctionType(
            type::Function(type::function::Result(type::void_, meta()), params, type::function::Flavor::Hook, meta()));
    }

    void setResultType(const Type& t) { children()[0].as<Function>().setResultType(t); }

    bool operator==(const Hook& other) const { return function() == other.function() && _engine == other._engine; }

    auto properties() const {
        return node::Properties{{"engine", to_string(_engine)},
                                {"unit_type", _unit_type.renderedRid()},
                                {"unit_field", _unit_field.renderedRid()}};
    }

private:
    Engine _engine = {};
    NodeRef _unit_type;
    NodeRef _unit_field;
};

/** Creates an AST node representing a `Hook`. */
inline Node to_node(Hook f) { return Node(std::move(f)); }

} // namespace spicy
