// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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
    Extern,          /**< function can be called from external C++ code */
    ExternNoSuspend, /**< function can be called from external C++ code, and is guaranteed to not suspend. */
    Standard         /**< default, nothing special */
};

namespace detail {
constexpr util::enum_::Value<CallingConvention> conventions[] = {
    {CallingConvention::Extern, "extern"},
    {CallingConvention::ExternNoSuspend, "extern-no-suspend"},
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

    const auto& id() const { return child<ID>(0); }
    const auto& type() const { return child<Type>(1).as<Type>(); }
    NodeRef typeRef() { return NodeRef(children()[1]); }
    const auto& ftype() const { return child<Type>(1).as<type::Function>(); }
    auto body() const { return children()[2].tryAs<Statement>(); }
    auto attributes() const { return children()[3].tryAs<AttributeSet>(); }
    auto callingConvention() const { return _cc; }
    bool isStatic() const { return AttributeSet::find(attributes(), "&static").has_value(); }

    bool operator==(const Function& other) const {
        return id() == other.id() && type() == other.type() && body() == other.body() &&
               attributes() == other.attributes() && callingConvention() == other.callingConvention();
    }

    void setBody(const Statement& b) { children()[2] = b; }
    void setID(const ID& id) { children()[0] = id; }
    void setFunctionType(const type::Function& ftype) { children()[1] = ftype; }
    void setResultType(const Type& t) { children()[1].as<type::Function>().setResultType(t); }

    /** Internal method for use by builder API only. */
    Node& _typeNode() { return children()[1]; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"cc", to_string(_cc)}}; }

private:
    function::CallingConvention _cc = function::CallingConvention::Standard;
};

/** Creates an AST node representing a `Function`. */
inline Node to_node(Function f) { return Node(std::move(f)); }

} // namespace hilti
