// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a statement representing a declaration.. */
class Declaration : public NodeBase, public hilti::trait::isStatement {
public:
    Declaration(hilti::Declaration d, Meta m = Meta()) : NodeBase({std::move(d)}, std::move(m)) {}

    const auto& declaration() const { return child<::hilti::Declaration>(0); }
    auto declarationRef() const { return NodeRef(children()[0]); }

    bool operator==(const Declaration& other) const { return declaration() == other.declaration(); }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::statement
