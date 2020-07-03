// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>

namespace hilti {
namespace declaration {

/**
 * AST node for a declaration that forwards all methods to another one. This
 * is useful to bind to nodes with declarations that may later be replaced.
 * Note that this is not meant to be used as the original definition of a
 * declaration itself; the code generator won't emit any corresponding
 * declaration for it.
 */
class Forward : public NodeBase, public hilti::trait::isDeclaration {
public:
    using Callback = std::function<Declaration()>;

    Forward(Callback cb, Meta m = Meta()) : NodeBase(std::move(m)), _cb(std::move(cb)) {}

    auto callback() const { return _cb; }

    bool operator==(const Forward& other) const { return _cb() == other._cb(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return _cb().isConstant(); }
    /** Implements `Declaration` interface. */
    ID id() const { return _cb().id(); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _cb().linkage(); }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return _cb().displayName() + " (forwarded)"; }
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{}}; }

private:
    Callback _cb;
};

} // namespace declaration
} // namespace hilti
