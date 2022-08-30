// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/base/optional-ref.h>

namespace hilti::type {

namespace vector {

/** AST node for a vector iterator type. */
class Iterator : public TypeBase {
public:
    Iterator(Type etype, bool const_, Meta m = Meta())
        : TypeBase(nodes(std::move(etype)), std::move(m)), _const(const_) {}
    Iterator(Wildcard /*unused*/, bool const_ = true, Meta m = Meta())
        : TypeBase(nodes(type::unknown), std::move(m)), _wildcard(true), _const(const_) {}

    /** Returns true if the container elements aren't modifiable. */
    bool isConstant() const { return _const; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }

    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(dereferencedType(), rstate);
    }

    optional_ref<const Type> dereferencedType() const override { return child<Type>(0); }
    bool isWildcard() const override { return _wildcard; }
    std::vector<Node> typeParameters() const override { return children(); }
    node::Properties properties() const override { return node::Properties{{"const", _const}}; }

    bool _isAllocable() const override { return true; }
    bool _isIterator() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isParameterized() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    bool operator==(const Iterator& other) const { return dereferencedType() == other.dereferencedType(); }

private:
    bool _wildcard = false;
    bool _const = false;
};

} // namespace vector

/** AST node for a vector type. */
class Vector : public TypeBase {
public:
    Vector(const Type& t, const Meta& m = Meta())
        : TypeBase(nodes(vector::Iterator(t, true, m), vector::Iterator(t, false, m)), m) {}
    Vector(Wildcard /*unused*/, const Meta& m = Meta())
        : TypeBase(nodes(vector::Iterator(Wildcard{}, true, m), vector::Iterator(Wildcard{}, false, m)), m),
          _wildcard(true) {}

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }

    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(iteratorType(true), rstate) &&
               type::detail::isResolved(iteratorType(false), rstate);
    }

    optional_ref<const Type> elementType() const override { return child<vector::Iterator>(0).dereferencedType(); }

    optional_ref<const Type> iteratorType(bool const_) const override {
        return const_ ? child<Type>(0) : child<Type>(1);
    }

    bool isWildcard() const override { return _wildcard; }
    std::vector<Node> typeParameters() const override { return children(); }
    node::Properties properties() const override { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isParameterized() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    bool operator==(const Vector& other) const { return elementType() == other.elementType(); }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
