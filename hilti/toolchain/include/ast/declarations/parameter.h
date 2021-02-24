// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>

namespace hilti {
namespace declaration {

namespace parameter {

/** Type of a `Parameter`. */
enum class Kind {
    Unknown, /**< not specified */
    Copy,    /**< `copy` parameter */
    In,      /**< `in` parameter */
    InOut    /**< `inout` parameter */
};

namespace detail {
constexpr util::enum_::Value<Kind> kinds[] = {
    {Kind::Unknown, "unknown"},
    {Kind::Copy, "copy"},
    {Kind::In, "in"},
    {Kind::InOut, "inout"},
};
} // namespace detail

constexpr auto to_string(Kind k) { return util::enum_::to_string(k, detail::kinds); }

namespace kind {
constexpr auto from_string(const std::string_view& s) { return util::enum_::from_string<Kind>(s, detail::kinds); }
} // namespace kind

} // namespace parameter

/** AST node for a declaration of a function parameter. */
class Parameter : public NodeBase, public hilti::trait::isDeclaration {
public:
    Parameter(ID id, hilti::Type type, parameter::Kind kind, std::optional<hilti::Expression> default_, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), std::move(default_)), std::move(m)), _kind(kind) {}

    Parameter(ID id, hilti::Type type, parameter::Kind kind, std::optional<hilti::Expression> default_,
              bool is_struct_param, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), std::move(default_)), std::move(m)),
          _kind(kind),
          _is_struct_param(is_struct_param) {}

    Parameter() : NodeBase({node::none, node::none, node::none}, Meta()) {}

    auto type() const { return type::effectiveType(child<hilti::Type>(1)); }

    auto default_() const { return childs()[2].tryReferenceAs<hilti::Expression>(); }
    auto kind() const { return _kind; }
    auto isStructParameter() const { return _is_struct_param; }

    bool operator==(const Parameter& other) const {
        return id() == other.id() && type() == other.type() && kind() == other.kind() && default_() == other.default_();
    }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return _kind == parameter::Kind::In; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return Linkage::Private; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "parameter"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const {
        return node::Properties{{"kind", to_string(_kind)}, {"is_struct_param", _is_struct_param}};
    }

    /**
     * Returns a new parameter declaration with its type replaced.
     *
     * @param d original declaration
     * @param b new type
     * @return new declaration that's equal to original one but with the type replaced
     */
    static Declaration setType(const Parameter& d, std::optional<hilti::Type> t) {
        auto x = Declaration(d)._clone().as<Parameter>();
        if ( t )
            x.childs()[1] = *t;
        else
            x.childs()[1] = node::none;

        return x;
    }

    /**
     * Returns a new parameter declaration with the default expression replaced.
     *
     * @param d original declaration
     * @param e new default expresssion
     * @return new declaration that's equal to original one but with the default expression replaced
     */
    static Declaration setDefault(const Parameter& d, const hilti::Expression& e) {
        auto x = Declaration(d)._clone().as<Parameter>();
        x.childs()[2] = e;
        return x;
    }

    /**
     * Returns a new parameter declaration with the is-struct-parameter option set.
     * @param d original declaration
     * @return new declaration that's equal to original one but with the flag set
     */
    static Declaration setIsStructParameter(const Parameter& d) {
        auto x = Declaration(d)._clone().as<Parameter>();
        x._is_struct_param = true;
        return x;
    }

private:
    parameter::Kind _kind = parameter::Kind::Unknown;
    bool _is_struct_param = false;
};

/** Returns true if two parameters are different only by name of their ID. */
inline bool areEquivalent(const Parameter& p1, const Parameter& p2) {
    if ( p1.kind() != p2.kind() || p1.default_() != p2.default_() )
        return false;

    auto auto1 = p1.type().tryAs<type::Auto>();
    auto auto2 = p2.type().tryAs<type::Auto>();

    if ( auto1 || auto2 )
        return true;

    return p1.type() == p2.type();
}

} // namespace declaration
} // namespace hilti
