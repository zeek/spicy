// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

namespace hilti::statement {

namespace try_ {

/**
 * AST node for a `catch` block.
 */
class Catch : public NodeBase {
public:
    Catch(hilti::Statement body, Meta m = Meta()) : NodeBase(nodes(node::none, std::move(body)), std::move(m)) {}
    Catch(const hilti::Declaration& param, Statement body, Meta m = Meta())
        : NodeBase(nodes(param, std::move(body)), std::move(m)) {
        if ( ! param.isA<hilti::declaration::Parameter>() )
            logger().internalError("'catch' hilti::Declaration must be parameter");
    }
    Catch() = default;

    auto parameter() const { return children()[0].tryAs<declaration::Parameter>(); }
    auto parameterRef() const {
        return children()[0].isA<declaration::Parameter>() ? NodeRef(children()[0]) : NodeRef();
    }
    const auto& body() const { return child<hilti::Statement>(1); }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return children()[1]; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Catch& other) const { return parameter() == other.parameter() && body() == other.body(); }
};

} // namespace try_

/** AST node for a "try" statement. */
class Try : public NodeBase, public hilti::trait::isStatement {
public:
    Try(hilti::Statement body, std::vector<try_::Catch> catches, Meta m = Meta())
        : NodeBase(nodes(std::move(body), std::move(catches)), std::move(m)) {}

    const auto& body() const { return child<hilti::Statement>(0); }
    auto catches() const { return children<try_::Catch>(1, -1); }

    bool operator==(const Try& other) const { return body() == other.body() && catches() == other.catches(); }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return children()[0]; }

    /** Internal method for use by builder API only. */
    auto& _lastCatchNode() { return children().back(); }

    /** Internal method for use by builder API only. */
    void _addCatch(try_::Catch catch_) { addChild(std::move(catch_)); }

    /** Implements the `Statement` interface. */
    auto isEqual(const hilti::Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::statement
