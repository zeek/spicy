// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <set>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/node.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>

namespace hilti {

namespace function {

/** A function's calling convention. */
enum class CallingConvention {
    Extern,  /**< function can be called from external C++ code */
    Standard /**< default, nothing special */
};

namespace detail {
constexpr util::enum_::Value<CallingConvention> conventions[] = {
    {CallingConvention::Extern, "extern"},
    {CallingConvention::Standard, "<standard>"},
};
} // namespace detail

constexpr auto to_string(CallingConvention cc) { return util::enum_::to_string(cc, detail::conventions); }

namespace calling_convention {
constexpr inline auto from_string(const std::string_view& s) {
    return util::enum_::from_string<CallingConvention>(s, detail::conventions);
}
} // namespace calling_convention

} // namespace function

/** AST node representing a function. */
class Function : public NodeBase {
public:
    Function(ID id, Type type, std::optional<Statement> body,
             function::CallingConvention cc = function::CallingConvention::Standard,
             std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), std::move(body), std::move(attrs)), std::move(m)), _cc(cc) {}

    Function() : NodeBase(nodes(node::none, node::none, node::none, node::none), Meta()) {}

    auto id() const { return child<ID>(0); }
    auto type() const { return type::effectiveType(child<Type>(1)).as<type::Function>(); }
    auto body() const { return childs()[2].tryAs<Statement>(); }
    auto attributes() const { return childs()[3].tryAs<AttributeSet>(); }
    auto callingConvention() const { return _cc; }
    auto isStatic() const { return AttributeSet::find(attributes(), "&static"); }

    bool operator==(const Function& other) const {
        return id() == other.id() && type() == other.type() && body() == other.body() &&
               attributes() == other.attributes() && callingConvention() == other.callingConvention();
    }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"cc", to_string(_cc)}}; }

    /**
     * Returns a new funnction with the body replaced.
     *
     * @param d original function
     * @param b new body
     * @return new function that's equal to original one but with the body replaced
     */
    static Function setBody(const Function& d, const Statement& b) {
        auto x = Function(d);
        x.childs()[2] = b;
        return x;
    }

private:
    function::CallingConvention _cc = function::CallingConvention::Standard;
};

/** Creates an AST node representing a `Function`. */
inline Node to_node(Function f) { return Node(std::move(f)); }

} // namespace hilti
