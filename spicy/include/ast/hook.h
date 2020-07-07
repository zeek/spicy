// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/function.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/engine.h>

namespace spicy {

/** AST node representing a Spicy unit hook. */
class Hook : public Function {
public:
    Hook(const std::vector<type::function::Parameter>& params, std::optional<Statement> body, Engine engine,
         std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : Function(ID("<hook>"),
                   type::Function(type::function::Result(type::Void(), m), params, type::function::Flavor::Hook, m),
                   std::move(body), hilti::function::CallingConvention::Standard, std::move(attrs), std::move(m)),
          _engine(engine) {}

    Hook() = default;

    Engine engine() const { return _engine; }
    bool isForEach() const { return AttributeSet::find(attributes(), "foreach").has_value(); }
    bool isDebug() const { return AttributeSet::find(attributes(), "%debug").has_value(); }

    std::optional<Expression> priority() const {
        if ( auto p = AttributeSet::find(attributes(), "priority") )
            return *p->valueAs<Expression>();

        return {};
    }

    bool operator==(const Hook& other) const {
        return static_cast<Function>(*this) == static_cast<Function>(other) && // NOLINT (cppcoreguidelines-slicing)
               _engine == other._engine;
    }

    auto properties() const { return Function::properties() + node::Properties{{"engine", to_string(_engine)}}; }

private:
    Engine _engine = {};
};

/** Creates an AST node representing a `Hook`. */
inline Node to_node(Hook f) { return Node(std::move(f)); }

} // namespace spicy
