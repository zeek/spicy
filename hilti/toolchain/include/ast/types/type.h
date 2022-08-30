// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/any.h>

namespace hilti::type {

/** AST node for a type representing a type value. */
class Type_ : public TypeBase {
public:
    Type_(Type t, Meta m = Meta()) : TypeBase(nodes(std::move(t)), std::move(m)) {}
    Type_(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(nodes(type::Any()), std::move(m)), _wildcard(true) {}

    const auto& typeValue() const { return child<Type>(0); }

    bool operator==(const Type_& other) const { return typeValue() == other.typeValue(); }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return type::detail::isResolved(typeValue(), rstate); }
    bool isWildcard() const override { return _wildcard; }
    node::Properties properties() const override { return node::Properties{}; }

    std::vector<Node> typeParameters() const override { return children(); }
    bool _isParameterized() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
