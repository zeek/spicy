// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/node_ref.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/base/logger.h>

namespace hilti {
namespace expression {

/** AST node for a expression representing a resolved ID. */
class ResolvedID : public NodeBase, hilti::trait::isExpression {
public:
    ResolvedID(ID id, NodeRef r, Meta m = Meta()) : NodeBase({std::move(id)}, std::move(m)), _node(std::move(r)) {
        assert(_node && _node->isA<Declaration>());
    }

    const auto& id() const { return child<ID>(0); }
    const auto& declaration() const {
        assert(_node);
        return _node->as<Declaration>();
    }

    bool isValid() const { return static_cast<bool>(_node); }
    auto rid() const { return _node.rid(); }

    bool operator==(const ResolvedID& other) const {
        return id() == other.id() && declaration() == other.declaration();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return ! declaration().isConstant(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return false; }
    /** Implements `Expression` interface. */
    Type type() const;
    /** Implements `Expression` interface. */
    bool isConstant() const;
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const {
        return _node ? node::Properties{{"resolved", _node.renderedRid()}} : node::Properties{{}};
    }

private:
    NodeRef _node;
};

/** AST node for a expression representing an unresolved ID. */
class UnresolvedID : public NodeBase, hilti::trait::isExpression {
public:
    UnresolvedID(ID id, Meta m = Meta()) : NodeBase({std::move(id)}, std::move(m)) {}

    const auto& id() const { return child<ID>(0); }

    bool operator==(const UnresolvedID& other) const { return id() == other.id(); }

    // Expression interface.
    bool isLhs() const { return true; }
    bool isTemporary() const { return false; }
    Type type() const { return type::unknown; }
    auto isConstant() const { return false; }
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
