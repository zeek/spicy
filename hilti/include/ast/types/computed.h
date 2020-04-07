// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/node_ref.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace type {

/**
 * AST node for a type computed dynamically from another node that's
 * potentially not resolved at first yet. This works either through a
 * callback that executes at time the type is accessed, with access to the
 * original node; or through an expression which's type at the time of access
 * determined the result.
 *
 * @note This class gets a full set of traits, so that it can forward all
 * method calls to the resulting type.
 */
class Computed : public TypeBase,
                 trait::hasDynamicType,
                 type::trait::isParameterized,
                 type::trait::isViewable,
                 trait::isDereferencable,
                 trait::isIterable {
public:
    using Callback = std::function<Type(Node&)>;
    Computed(NodeRef r, Meta m = Meta()) : TypeBase(nodes(node::none), std::move(m)), _node(std::move(std::move(r))) {}
    Computed(NodeRef r, Callback cb, Meta m = Meta())
        : TypeBase(nodes(node::none), std::move(m)), _node(std::move(std::move(r))), _callback(std::move(cb)) {}
    Computed(Expression e, Meta m = Meta()) : TypeBase(nodes(std::move(e)), std::move(m)) {}
    Computed(Expression e, bool change_constness_to, Meta m = Meta())
        : TypeBase(nodes(std::move(e)), std::move(m)), _change_constness_to(change_constness_to) {}
    Computed(Type t, Meta m = Meta()) : TypeBase(nodes(std::move(t)), std::move(m)) {}
    Computed(Type t, Callback cb, Meta m = Meta())
        : TypeBase(nodes(std::move(t)), std::move(m)), _callback(std::move(cb)) {}

    Type type() const {
        if ( _node ) {
            if ( _callback )
                return type::effectiveType(_callback(*_node));
            else
                return type::effectiveType(_node->template as<Type>());
        }

        if ( auto e = childs()[0].tryAs<Expression>() ) {
            if ( ! _change_constness_to.has_value() )
                return e->type();

            if ( *_change_constness_to )
                return type::constant(e->type());

            return type::nonConstant(e->type());
        }

        if ( auto t = childs()[0].tryAs<Type>() ) {
            if ( _callback )
                return type::effectiveType(_callback(const_cast<Node&>(childs()[0])));
            else
                return *t;
        }

        return type::unknown;
    }

    bool operator==(const Computed& other) const { return type() == other.type(); }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const { return type() == other; }
    /** Implements the `Type` interface. */
    Type effectiveType() const { return type::effectiveType(type()); }

    std::vector<Node> typeParameters() const { return type().typeParameters(); }
    bool isWildcard() const { return type().isWildcard(); }
    Type iteratorType(bool const_) const { return type().iteratorType(const_); }
    Type viewType() const { return type().viewType(); }
    Type dereferencedType() const { return type().dereferencedType(); }
    Type elementType() const { return type().elementType(); }

    /** Implements the `Node` interface. */
    auto properties() const {
        return _node ? node::Properties{{"resolved", _node.renderedRid()}} : node::Properties{{}};
    }

private:
    NodeRef _node;
    Callback _callback;
    std::optional<bool> _change_constness_to;
};

} // namespace type
} // namespace hilti
