// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <functional>
#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/type.h>

namespace hilti::type {

namespace tuple {

/** AST node for a tuple element. */
class Element : public NodeBase {
public:
    explicit Element(Type t, Meta m = Meta()) : NodeBase(nodes(node::none, std::move(t)), std::move(m)) {}
    Element(ID id, Type t, Meta m = Meta())
        : NodeBase(nodes(id ? std::move(id) : node::none, std::move(t)), std::move(m)) {}
    Element(Meta m = Meta()) : NodeBase(nodes(node::none, node::none), std::move(m)) {}

    auto id() const { return children()[0].tryAs<ID>(); }
    const auto& type() const { return child<Type>(1); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Element& other) const { return id() == other.id() && type() == other.type(); }
};

inline Node to_node(Element f) { return Node(std::move(f)); }

} // namespace tuple

/** AST node for a tuple type. */
class Tuple : public TypeBase, trait::isAllocable, trait::isParameterized, trait::isSortable {
public:
    Tuple(std::vector<Type> t, Meta m = Meta()) : TypeBase(nodes(_typesToElements(std::move(t))), std::move(m)) {}
    Tuple(std::vector<tuple::Element> e, Meta m = Meta()) : TypeBase(nodes(std::move(e)), std::move(m)) {}
    Tuple(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {}

    auto elements() const { return children<tuple::Element>(0, -1); }
    std::optional<std::pair<int, const type::tuple::Element*>> elementByID(const ID& id) const;

    bool operator==(const Tuple& other) const {
        if ( _wildcard || other._wildcard )
            return _wildcard && other._wildcard;

        return elements() == other.elements();
    }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        const auto& cs = children();

        return std::all_of(cs.begin(), cs.end(), [&](const auto& c) {
            auto t = c.template tryAs<Type>();
            return ! t || type::detail::isResolved(*t, rstate);
        });
    }

    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"wildcard", _wildcard}}; }

private:
    std::vector<tuple::Element> _typesToElements(std::vector<Type>&& types) {
        std::vector<tuple::Element> elements;
        elements.reserve(types.size());
        for ( auto&& t : types )
            elements.emplace_back(std::move(t), t.meta());

        return elements;
    }

    bool _wildcard = false;
};

} // namespace hilti::type
