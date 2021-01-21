// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

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

    std::optional<hilti::declaration::Parameter> parameter() const {
        auto d = childs()[0].tryAs<hilti::Declaration>();
        if ( d )
            return d->as<hilti::declaration::Parameter>();

        return {};
    }

    const auto& body() const { return child<hilti::Statement>(1); }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return childs()[1]; }

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
    auto catches() const { return childs<try_::Catch>(1, -1); }

    bool operator==(const Try& other) const { return body() == other.body() && catches() == other.catches(); }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return childs()[0]; }

    /** Internal method for use by builder API only. */
    auto& _lastCatchNode() { return childs().back(); }

    /** Internal method for use by builder API only. */
    void _addCatch(try_::Catch catch_) { addChild(std::move(catch_)); }

    /** Implements the `Statement` interface. */
    auto isEqual(const hilti::Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace statement
} // namespace hilti
