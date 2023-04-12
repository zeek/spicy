// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <set>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/statements/expression.h>
#include <hilti/base/util.h>

namespace hilti {

/** AST node representing a HILTI module. */
class Module : public NodeBase, public node::WithDocString {
public:
    Module(ID id, Meta m = Meta()) : NodeBase({std::move(id), statement::Block({}, m)}, std::move(m)) {}

    Module(ID id, std::vector<Declaration> decls, Meta m = Meta())
        : NodeBase(nodes(std::move(id), statement::Block({}, m), std::move(decls)), std::move(m)) {}

    Module(ID id, std::vector<Declaration> decls, std::vector<Statement> stmts, const Meta& m = Meta())
        : NodeBase(nodes(std::move(id), statement::Block(std::move(stmts), m), std::move(decls)), m) {}

    Module() : NodeBase(nodes(ID(), statement::Block({}, Meta())), Meta()) {}

    const auto& id() const { return child<ID>(0); }
    const auto& statements() const { return child<statement::Block>(1); }
    auto declarations() const { return childrenOfType<Declaration>(); }
    auto declarationRefs() const { return childRefsOfType<Declaration>(); }

    bool isEmpty() const {
        // We always have an ID and a block as children.
        return children().size() <= 2 && statements().statements().empty();
    }

    /**
     * Removes any content from the module. The result is an empty module just
     * as if it had just been created. (The ID remains in place.)
     */
    void clear();

    /**
     * Returns a module's property declaration of a given name. If there's no
     * property declaration of that name, return an error. If there's more than
     * one of that name, it's undefined which one is returned.
     *
     * @param id name of the property to return
     */
    hilti::optional_ref<const declaration::Property> moduleProperty(const ID& id) const;

    /**
     * Returns all of module's property declarations of a given name. If
     * there's no property declaration of that ID, return an empty container.
     *
     * @param id name of the property to return; leave unset for returning all
     */
    hilti::node::Set<declaration::Property> moduleProperties(const std::optional<ID>& id) const;

    /**
     * Adds a declaration to the module. It will be appended to the current
     * list of declarations.
     *
     * Note this is a mutating function. `Module` is an exception among AST
     * classes in that we allow to modify existing instances. Changes will be
     * reflected in all copies of this instance.
     */
    void add(Declaration n) { addChild(std::move(n)); }

    /**
     * Adds a top-level statement to the module. It will be appended to the
     * end of the current list of statements and execute at module initialize
     * time.
     *
     * Note this is a mutating function. `Module` is an exception among AST
     * classes in that we allow to modify existing instances. Changes will be
     * reflected in all copies of this instance.
     *
     */
    void add(Statement s) { children()[1].as<statement::Block>()._add(std::move(s)); }

    /**
     * Adds a top-level expression to the module. It will be appended to the
     * end of the current list of statements and be evaluated at module
     * initialize time.
     *
     * Note this is a mutating function. `Module` is an exception among AST
     * classes in that we allow to modify existing instances. Changes will be
     * reflected in all copies of this instance.
     *
     */
    void add(Expression e) { add(statement::Expression(std::move(e))); }

    /**
     * Saves a node along with the module, but outside of the actual AST. This
     * allows keeping references to the node's sub-AST valid while not making
     * the node itself part of the AST. That's especially useful when
     * transforming nodes from one representation to another while other parts
     * of the AST are still referring to the original once.
     *
     * @param n node to retain with all of its children
     * @returns a reference to the internally stored node
     */
    NodeRef preserve(const Node& n) {
        _preserved.push_back(n);
        return NodeRef(_preserved.back());
    }

    /** Destroys any nodes retained previously through `preserve()`. */
    void destroyPreservedNodes();

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    std::vector<Node> _preserved;
};

/** Creates an AST node representing a `Module`. */
inline Node to_node(Module i) { return Node(std::move(i)); }

} // namespace hilti
