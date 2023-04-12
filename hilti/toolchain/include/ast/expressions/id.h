// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/auto.h>
#include <hilti/base/logger.h>

namespace hilti::expression {

/** AST node for a expression representing a resolved ID. */
class ResolvedID : public NodeBase, hilti::trait::isExpression {
public:
    ResolvedID(ID id, NodeRef d, Meta m = Meta()) : NodeBase(nodes(std::move(id)), std::move(m)), _d(std::move(d)) {}

    const auto& id() const { return child<ID>(0); }
    const auto& declaration() const { return _d->as<Declaration>(); }
    const auto& declarationRef() const { return _d; }

    bool operator==(const ResolvedID& other) const {
        return id() == other.id() && declaration() == other.declaration();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return ! declaration().isConstant(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return false; }
    /** Implements `Expression` interface. */
    const Type& type() const;
    /** Implements `Expression` interface. */
    bool isConstant() const;
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"rid", _d.rid()}}; }

private:
    NodeRef _d;
};

/** AST node for a expression representing an unresolved ID. */
class UnresolvedID : public NodeBase, hilti::trait::isExpression {
public:
    UnresolvedID(ID id, Meta m = Meta()) : NodeBase(nodes(std::move(id), type::auto_), std::move(m)) {}

    const auto& id() const { return child<ID>(0); }

    bool operator==(const UnresolvedID& other) const { return id() == other.id(); }

    // Expression interface.
    bool isLhs() const { return true; }
    bool isTemporary() const { return false; }
    const Type& type() const { return child<Type>(1); }
    auto isConstant() const { return false; }
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
