// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>

namespace hilti {

/** Base class for expression nodes. */
class Expression : public Node {
public:
    /** Returns true if the expression's type is constant. */
    auto isConstant() const { return type()->isConstant(); }

    /** Returns true if expression's type has been resolved. */
    auto isResolved(node::CycleDetector* cd = nullptr) const { return type()->type()->isResolved(cd); }

    /** Returns the expression's HILTI type when evaluated. */
    virtual QualifiedType* type() const = 0;

protected:
    Expression(ASTContext* ctx, node::Tags node_tags, Nodes children, Meta meta)
        : Node::Node(ctx, node_tags, std::move(children), std::move(meta)) {}

    std::string _dump() const override;

    HILTI_NODE_0(Expression, override);
};

namespace expression {

/** Returns true if all of a range's expressions have fully resolved types. */
inline bool areResolved(const node::Range<Expression>& exprs) {
    for ( const auto& e : exprs ) {
        if ( ! e->isResolved() )
            return false;
    }

    return true;
}

} // namespace expression

} // namespace hilti
