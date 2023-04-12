// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expressions/void.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/error.h>
#include <hilti/ast/types/operand-list.h>
#include <hilti/base/util.h>

namespace hilti {
namespace type {

namespace function {

/**
 * A function's flavor diffrentiates between a set of "function-like"
 * language element.
 */
enum class Flavor {
    Hook,    /**< a hook */
    Method,  /**< a struct method */
    Standard /**< a normal function */
};

namespace detail {
constexpr util::enum_::Value<Flavor> flavors[] = {
    {Flavor::Hook, "hook"},
    {Flavor::Method, "method"},
    {Flavor::Standard, "standard"},
};
} // namespace detail

constexpr auto to_string(Flavor f) { return util::enum_::to_string(f, detail::flavors); }

namespace flavor {
constexpr auto from_string(const std::string_view& s) { return util::enum_::from_string<Flavor>(s, detail::flavors); }
} // namespace flavor

/** AST node for a result type. */
class Result : public NodeBase {
public:
    Result(Type type, Meta m = Meta()) : NodeBase(nodes(std::move(type)), std::move(m)) {}

    Result() : NodeBase(nodes(node::none), Meta()) {}

    const auto& type() const { return child<Type>(0); }

    void setType(const Type& x) { children()[0] = x; }

    bool operator==(const Result& other) const { return type() == other.type(); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

using Parameter = declaration::Parameter;

namespace parameter {
using Kind = declaration::parameter::Kind;
} // namespace parameter

} // namespace function

class Function : public TypeBase, trait::isParameterized {
public:
    Function(Wildcard /*unused*/, Meta m = Meta())
        : TypeBase(nodes(function::Result(type::Error(m))), std::move(m)), _wildcard(true) {}
    Function(function::Result result, const std::vector<function::Parameter>& params,
             function::Flavor flavor = function::Flavor::Standard, Meta m = Meta())
        : TypeBase(nodes(std::move(result), util::transform(params, [](const auto& p) { return Declaration(p); })),
                   std::move(m)),
          _flavor(flavor) {}

    const auto& result() const { return child<function::Result>(0); }
    auto parameters() const { return children<function::Parameter>(1, -1); }
    auto parameterRefs() const { return childRefsOfType<type::function::Parameter>(); }
    auto flavor() const { return _flavor; }

    void setResultType(const Type& t) { children()[0].as<function::Result>().setType(t); }

    bool operator==(const Function& other) const {
        return result() == other.result() && parameters() == other.parameters();
    }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }

    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        if ( result().type().isA<type::Auto>() )
            // We treat this as resolved because (1) it doesn't need to hold up
            // other resolving, and (2) can lead to resolver dead-locks if we
            // let it.
            return true;

        if ( ! type::detail::isResolved(result().type(), rstate) )
            return false;

        for ( auto p = children().begin() + 1; p != children().end(); p++ ) {
            if ( ! p->as<function::Parameter>().isResolved(rstate) )
                return false;
        }

        return true;
    }

    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"flavor", to_string(_flavor)}}; }

private:
    bool _wildcard = false;
    function::Flavor _flavor = function::Flavor::Standard;
};

/**
 * Returns true if two function types are equivalent, even if not
 * identical. This for example allows parameter ID to be different.
 */
inline bool areEquivalent(const Function& f1, const Function& f2) {
    if ( ! (f1.result() == f2.result()) )
        return false;

    auto p1 = f1.parameters();
    auto p2 = f2.parameters();
    return std::equal(std::begin(p1), std::end(p1), std::begin(p2), std::end(p2),
                      [](const auto& p1, const auto& p2) { return areEquivalent(p1, p2); });
}

} // namespace type

inline Node to_node(type::function::Result t) { return Node(std::move(t)); }

} // namespace hilti
