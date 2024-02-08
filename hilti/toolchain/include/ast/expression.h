// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>

namespace hilti {

namespace type {
using ResolvedState = std::unordered_set<uintptr_t>;
}

/** Base class for expression nodes. */
class Expression : public Node {
public:
    ~Expression() override;

    /** Returns true if the expression's type is constant. */
    auto isConstant() const { return type()->isConstant(); }

    /** Returns true if expression's type has been resolved. */
    auto isResolved(node::CycleDetector* cd = nullptr) const { return type()->type()->isResolved(cd); }

    /** Returns the expression's HILTI type when evaluated. */
    virtual QualifiedTypePtr type() const = 0;

protected:
    Expression(ASTContext* ctx, Nodes children, Meta meta) : Node::Node(ctx, std::move(children), std::move(meta)) {}

    std::string _dump() const override;

    HILTI_NODE_BASE(hilti, Type);
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
