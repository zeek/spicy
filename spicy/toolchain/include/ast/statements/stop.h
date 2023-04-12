// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

#include <spicy/ast/aliases.h>

namespace spicy::statement {

/** AST node for Spicy's `stop` statement. */
class Stop : public hilti::NodeBase, public hilti::trait::isStatement {
public:
    Stop(Meta m = Meta()) : hilti::NodeBase(std::move(m)) {}

    bool operator==(const Stop& /* other */) const { return true; }

    // Statement interface.
    auto isEqual(const hilti::Statement& other) const { return hilti::node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return hilti::node::Properties{}; }
};

} // namespace spicy::statement
