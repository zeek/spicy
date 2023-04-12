// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::declaration {

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
class Parameter : public DeclarationBase {
public:
    Parameter(ID id, hilti::Type type, parameter::Kind kind, std::optional<hilti::Expression> default_,
              std::optional<AttributeSet> attrs, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), type::nonConstant(std::move(type)), std::move(default_),
                                std::move(attrs)),
                          std::move(m)),
          _kind(kind) {}

    Parameter(ID id, hilti::Type type, parameter::Kind kind, std::optional<hilti::Expression> default_,
              bool is_type_param, std::optional<AttributeSet> attrs, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), type::nonConstant(std::move(type)), std::move(default_),
                                std::move(attrs)),
                          std::move(m)),
          _kind(kind),
          _is_type_param(is_type_param) {}

    Parameter() : DeclarationBase({node::none, type::unknown, node::none, node::none}, Meta()) {}

    auto attributes() const { return children()[3].tryAs<AttributeSet>(); }
    auto default_() const { return children()[2].tryAs<hilti::Expression>(); }
    auto kind() const { return _kind; }
    const auto& type() const { return child<hilti::Type>(1); }
    auto isTypeParameter() const { return _is_type_param; }
    auto isResolved(type::ResolvedState* rstate) const { return type::detail::isResolved(type(), rstate); }

    void setDefault(const hilti::Expression& e) { children()[2] = e; }
    void setIsTypeParameter() { _is_type_param = true; }
    void setType(const hilti::Type& t) { children()[1] = t; }

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
    auto properties() const { return node::Properties{{"kind", to_string(_kind)}, {"is_type_param", _is_type_param}}; }

private:
    parameter::Kind _kind = parameter::Kind::Unknown;
    bool _is_type_param = false;
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

} // namespace hilti::declaration
