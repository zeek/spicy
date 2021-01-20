// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node_ref.h>
#include <hilti/ast/type.h>

namespace hilti {
namespace type {

/** AST node for a resolved type ID. */
class ResolvedID : public TypeBase, trait::hasDynamicType {
public:
    ResolvedID(::hilti::ID id, NodeRef r, Meta m = Meta())
        : TypeBase({std::move(id)}, std::move(m)), _node(std::move(std::move(r))) {
        assert(_node && _node->isA<declaration::Type>());
    }

    const auto& id() const { return child<::hilti::ID>(0); }
    auto declaration() const {
        assert(_node);
        return _node->as<Declaration>();
    }
    auto type() const {
        assert(_node);
        return _node->as<declaration::Type>().type();
    }
    bool isValid() const { return static_cast<bool>(_node); }
    const NodeRef& ref() const { return _node; }

    bool operator==(const ResolvedID& other) const { return type() == other.type(); }

    /** Implements the `Type` interface. */
    bool isEqual(const Type& other) const { return type() == type::effectiveType(other); }
    /** Implements the `Type` interface. */
    Type effectiveType() const { return type(); }

    /** Implements the `Node` interface. */
    auto properties() const {
        return _node ? node::Properties{{"resolved", _node.renderedRid()}} : node::Properties{{}};
    }

private:
    NodeRef _node;
};

/** AST node for an unresolved type ID. */
class UnresolvedID : public TypeBase {
public:
    UnresolvedID(::hilti::ID id, Meta m = Meta()) : TypeBase({std::move(id)}, std::move(m)) {}

    const auto& id() const { return child<::hilti::ID>(0); }

    bool operator==(const UnresolvedID& other) const { return id() == other.id(); }

    // Type interface.
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{}; }
};

} // namespace type
} // namespace hilti
