// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace type {

/** AST node for an "auto" type. */
class Auto : public TypeBase,
             trait::hasDynamicType,
             type::trait::isParameterized,
             type::trait::isViewable,
             trait::isDereferencable,
             trait::isIterable {
public:
    Auto(Meta m = Meta())
        : TypeBase(std::move(m)),
          _type(std::make_shared<std::shared_ptr<Node>>(std::make_shared<Node>(type::unknown))) {}

    const Type& type() const { return (*_type)->as<Type>(); }

    auto isSet() const { return ! (*_type)->isA<type::Unknown>(); }

    Node& typeNode() const { return **_type; }

    void linkTo(const Auto& other) { *_type = *other._type; }

    bool operator==(const Auto& other) const { return _type.get() == other._type.get(); }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const { return type() == other; }
    /** Implements the `Type` interface. */
    Type effectiveType() const {
        if ( isSet() )
            return type();
        else
            return *this; // don't resolve yet
    }

    std::vector<Node> typeParameters() const { return type().typeParameters(); }
    bool isWildcard() const { return type().isWildcard(); }
    Type iteratorType(bool const_) const { return type().iteratorType(const_); }
    Type viewType() const { return type().viewType(); }
    Type dereferencedType() const { return type().dereferencedType(); }
    Type elementType() const { return type().elementType(); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"resolves-to", Node(**_type).typename_()}}; }

private:
    std::shared_ptr<std::shared_ptr<Node>> _type;
};

} // namespace type
} // namespace hilti
