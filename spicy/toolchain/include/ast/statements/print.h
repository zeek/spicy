// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

#include <spicy/ast/aliases.h>

namespace spicy::statement {

class Print : public hilti::NodeBase, public hilti::trait::isStatement {
public:
    Print(std::vector<hilti::Expression> e, Meta m = Meta())
        : hilti::NodeBase(hilti::nodes(std::move(e)), std::move(m)) {}

    auto expressions() const { return children<hilti::Expression>(0, -1); }

    bool operator==(const Print& /* other */) const {
        // return expressions() == other.expressions(); FIXME
        return false;
    }

    // Statement interface.
    auto isEqual(const hilti::Statement& other) const { return hilti::node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return hilti::node::Properties{}; }
};

} // namespace spicy::statement
