// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>

namespace hilti {

/** AST node for an attribute. */
class Attribute : public Node {
public:
    /** Returns the name of the attribute, including the leading `&`. */
    const auto& tag() const { return _tag; }

    /** Returns true if an argument is associated with the attribute. */
    auto hasValue() const { return child(0) != nullptr; }

    /**
     * Returns the attribute associated with the node.
     *
     * @exception `std::out_of_range` if the attribute does not have an argument
     */
    Node* value() const { return child(0); }

    /**
     * Returns the expression argument associated with the attribute.
     *
     * @return the argument, or an error if the attribute does not have an
     * argument, or if it's not an expression.
     */
    Result<Expression*> valueAsExpression() const;

    /**
     * Returns the expression argument associated with the attribute as a
     * string, assuming it represents a constant integer value.
     *
     * @return the argument, or an error if the attribute does not have an
     * argument, or if it's not a constant string.
     */
    Result<std::string> valueAsString() const;

    /**
     * Returns the expression argument associated with the attribute as a
     * signed integer, assuming it represents a constant integer value. Both
     * signed and unsigned integer values are accepted, with the latter cased
     * into signed for the return value
     *
     * @return the argument, or an error if the attribute does not have an
     * argument, or if it's not a constant integer.
     */
    Result<int64_t> valueAsInteger() const;

    /**
     * Coerce the attribute's expression value to a specified type, modifying
     * the node in place.
     *
     * @return A successful return value if either the coercion succeeded
     * (then the result's value is true), or nothing was to be done (then the
     * result's value is false); a failure if a coercion would have been
     * necessary, but failed, or the attribute does not have a expression value.
     */
    Result<bool> coerceValueTo(Builder* builder, QualifiedType* dst);

    node::Properties properties() const final {
        auto p = node::Properties{{"tag", _tag}};
        return Node::properties() + p;
    }

    /**
     * Factory for an attribute coming with an argument. The argument must be
     * an AST node representing an expression.
     *
     * @param tag name of the attribute, including the leading `&`
     * @param v node representing the argument to associate with the attribute; must be an expression
     * @param m meta data to associate with the node
     */
    static auto create(ASTContext* ctx, const std::string& tag, Expression* v, const Meta& m = Meta()) {
        return ctx->make<Attribute>(ctx, {v}, tag, m);
    }

    /**
     * Factory for an attribute with no argument.
     *
     * @param tag name of the attribute, including the leading `&`
     * @param m meta data to associate with the node
     */
    static auto create(ASTContext* ctx, const std::string& tag, const Meta& m = Meta()) {
        return create(ctx, tag, nullptr, m);
    }

protected:
    Attribute(ASTContext* ctx, Nodes children, std::string tag, Meta m = Meta())
        : Node(ctx, NodeTags, std::move(children), std::move(m)), _tag(std::move(tag)) {}

    std::string _dump() const override;

    HILTI_NODE_0(Attribute, final);

private:
    std::string _tag;
};

/** AST node holding a set of `Attribute` nodes. */
class AttributeSet : public Node {
public:
    /** Returns the set's attributes. */
    auto attributes() const { return children<Attribute>(0, {}); }

    /**
     * Retrieves an attribute with a given name from the set. If multiple
     * attributes with that tag exist, it's undefined which one is returned.
     *
     * @return attribute if found
     */
    Attribute* find(std::string_view tag) const;

    /**
     * Retrieves all attributes with a given name from the set.
     *
     * @return all attributes with matching name
     */
    hilti::node::Set<Attribute> findAll(std::string_view tag) const;

    /**
     * Returns true if there's an attribute with a given name in the set.
     *
     * @param true if found
     */
    bool has(std::string_view tag) const { return find(tag) != nullptr; }

    /** Adds an attribute to the set. */
    void add(ASTContext* ctx, Attribute* a) { addChild(ctx, a); }

    /** Removes all attributes of the given tag. */
    void remove(std::string_view tag);

    /** Returns true if the set has at least one element. */
    operator bool() const { return ! attributes().empty(); }

    static auto create(ASTContext* ctx, Attributes attrs = {}, Meta m = Meta()) {
        return ctx->make<AttributeSet>(ctx, Nodes{std::move(attrs)}, std::move(m));
    }

protected:
    /**
     * Constructs a set from from a vector of attributes.
     *
     * @param a vector to initialize attribute set from
     * @param m meta data to associate with the node
     */
    explicit AttributeSet(ASTContext* ctx, Nodes children, Meta m = Meta())
        : Node(ctx, NodeTags, std::move(children), std::move(m)) {}

    /**
     * Constructs an empty set.
     *
     * @param m meta data to associate with the node
     */
    AttributeSet(ASTContext* ctx, Meta m = Meta()) : Node(ctx, {node::tag::AttributeSet}, {}, std::move(m)) {}

    std::string _dump() const override;

    HILTI_NODE_0(AttributeSet, final);
};

} // namespace hilti
