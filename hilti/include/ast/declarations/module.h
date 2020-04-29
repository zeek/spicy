// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>


#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/meta.h>
#include <hilti/ast/module.h>
#include <hilti/ast/node.h>
#include <hilti/ast/node_ref.h>
#include <hilti/base/result.h>
#include <hilti/base/type_erase.h>

namespace hilti {
namespace declaration {

/** AST node for an AST's top-level module declaration. */
class Module : public NodeBase, public hilti::trait::isDeclaration {
public:
    /**
     * Constructor.
     *
     * @param root reference to root node of module's AST; must be a ``Module`` node.
     */
    Module(NodeRef root, Meta m = Meta()) : NodeBase(std::move(m)), _root(std::move(root)) {
        assert(_root && _root->isA<hilti::Module>());
    }

    Node& root() const { return *_root; }

    bool operator==(const Module& other) const { return id() == other.id(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    ID id() const { return _root->as<hilti::Module>().id(); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return Linkage::Public; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "module"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"id", id()}}; }

private:
    NodeRef _root;
};

} // namespace declaration
} // namespace hilti
