// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <utility>
#include <vector>

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
    using Callback2 = std::function<Type(Node&, Node&)>;
    Computed(NodeRef r, Meta m = Meta()) : TypeBase(nodes(node::none), std::move(m)), _node(std::move(r)) {}
    Computed(NodeRef r, Callback cb, Meta m = Meta())
        : TypeBase(nodes(node::none), std::move(m)), _node(std::move(r)), _callback(std::move(cb)) {}
    Computed(Expression e, Meta m = Meta()) : TypeBase(nodes(std::move(e)), std::move(m)) {}
    Computed(NodeRef r1, NodeRef r2, Callback2 cb, Meta m = Meta())
        : TypeBase(nodes(node::none), std::move(m)),
          _node(std::move(r1)),
          _node2(std::move(r2)),
          _callback2(std::move(cb)) {}
    Computed(Expression e, Callback cb, Meta m = Meta())
        : TypeBase(nodes(std::move(e)), std::move(m)), _callback(std::move(cb)) {}
    Computed(Type t, Meta m = Meta()) : TypeBase(nodes(std::move(t)), std::move(m)) {}
    Computed(Type t, Callback cb, Meta m = Meta())
        : TypeBase(nodes(std::move(t)), std::move(m)), _callback(std::move(cb)) {}
    Computed(Type t, Node n, Callback2 cb2, Meta m = Meta())
        : TypeBase(nodes(std::move(t), std::move(n)), std::move(m)), _callback2(std::move(cb2)) {}

    Type type() const {
        if ( _node ) {
            if ( _callback )
                return type::effectiveType(_callback(*_node));
            else if ( _callback2 ) {
                assert(_node2);
                return type::effectiveType(_callback2(*_node, *_node2));
            }
            else
                return type::effectiveType(_node->template as<Type>());
        }

        if ( auto e = childs()[0].tryAs<Expression>() ) {
            if ( _callback )
                return type::effectiveType(_callback(const_cast<Node&>(childs()[0])));
            else if ( _callback2 )
                return type::effectiveType(_callback2(const_cast<Node&>(childs()[0]), const_cast<Node&>(childs()[1])));

            if ( ! _change_constness_to.has_value() )
                return e->type();

            if ( *_change_constness_to )
                return type::constant(e->type());

            return type::nonConstant(e->type());
        }

        if ( auto t = childs()[0].tryAs<Type>() ) {
            if ( _callback )
                return type::effectiveType(_callback(const_cast<Node&>(childs()[0])));
            else if ( _callback2 )
                return type::effectiveType(_callback2(const_cast<Node&>(childs()[0]), const_cast<Node&>(childs()[1])));
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
        node::Properties props;
        if ( _node )
            props.insert({"resolved", _node.renderedRid()});

        if ( _node2 )
            props.insert({"resolved2", _node2.renderedRid()});

        props.insert({"rid", _node.renderedRid()});
        return props;
    }

private:
    NodeRef _node;
    NodeRef _node2;
    Callback _callback;
    Callback2 _callback2;
    std::optional<bool> _change_constness_to;
};

} // namespace type
} // namespace hilti
