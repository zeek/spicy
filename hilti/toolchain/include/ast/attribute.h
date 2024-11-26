// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>

namespace hilti {

/** AST node for an attribute. */
class Attribute : public Node {
public:
    enum class Kind {
        EOD,
        UNTIL,
        UNTIL_INCLUDING,
        PARSE_AT,
        PARSE_FROM,
        SIZE,
        MAX_SIZE,
        IPV4,
        IPV6,
        TYPE,
        COUNT,
        SYNCHRONIZE,
        DEFAULT,
        ANONYMOUS,
        INTERNAL,
        OPTIONAL,
        STATIC,
        NO_EMIT,
        ON_HEAP,
        NOSUB,
        CXXNAME,
        HAVE_PROTOTYPE,
        PRIORITY,
        CONVERT,
        WHILE,
        REQUIRES,
        BYTE_ORDER_,
        BIT_ORDER,
        CHUNKED,
        ORIGINATOR,
        RESPONDER,
        TRY,
        NEEDED_BY_FEATURE,
        REQUIRES_TYPE_FEATURE,
        ALWAYS_EMIT,
        TRANSIENT,
        ANCHOR,

        // Hooks
        DEBUG,
        ERROR,
        FOREACH,
    };

    /** Returns the kind of the attribute, derived from its tag. */
    const auto& kind() const { return _kind; }

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

    /** Returns whether `kind` is in `kinds` */
    static bool isOneOf(Kind kind, std::initializer_list<Kind> kinds) {
        return std::find(kinds.begin(), kinds.end(), kind) != kinds.end();
    }

    /** Transforms a tag name into the appropriate enum value. */
    static std::optional<Kind> tagToKind(std::string_view tag);

    /** Transforms a kind into its name for diagnostics. */
    static std::string_view kindToString(Kind kind);

    /** A non-static alternative to get an attribute's string representation. */
    std::string_view attributeName() const { return kindToString(_kind); }

    node::Properties properties() const final {
        auto p = node::Properties{{"tag", std::string{attributeName()}}};
        return Node::properties() + p;
    }

    /**
     * Factory for an attribute coming with an argument. The argument must be
     * an AST node representing an expression.
     *
     * @param kind the attribute's internal representation
     * @param v node representing the argument to associate with the attribute; must be an expression
     * @param m meta data to associate with the node
     */
    static auto create(ASTContext* ctx, Kind kind, Expression* v, const Meta& m = Meta()) {
        return ctx->make<Attribute>(ctx, {v}, kind, m);
    }

    /**
     * Factory for an attribute with no argument.
     *
     * @param kind the attribute's internal representation
     * @param m meta data to associate with the node
     */
    static auto create(ASTContext* ctx, Kind kind, const Meta& m = Meta()) { return create(ctx, kind, nullptr, m); }

protected:
    Attribute(ASTContext* ctx, Nodes children, Kind kind, Meta m = Meta())
        : Node(ctx, NodeTags, std::move(children), std::move(m)), _kind(kind) {}

    std::string _dump() const override;

    HILTI_NODE_0(Attribute, final);

private:
    Kind _kind;
    static inline std::map<std::string_view, Kind> _attr_map{
        {"&eod", Attribute::Kind::EOD},
        {"&until", Attribute::Kind::UNTIL},
        {"&until-including", Attribute::Kind::UNTIL_INCLUDING},
        {"&parse-at", Attribute::Kind::PARSE_AT},
        {"&parse-from", Attribute::Kind::PARSE_FROM},
        {"&size", Attribute::Kind::SIZE},
        {"&max-size", Attribute::Kind::MAX_SIZE},
        {"&ipv4", Attribute::Kind::IPV4},
        {"&ipv6", Attribute::Kind::IPV6},
        {"&type", Attribute::Kind::TYPE},
        {"&count", Attribute::Kind::COUNT},
        {"&synchronize", Attribute::Kind::SYNCHRONIZE},
        {"&default", Attribute::Kind::DEFAULT},
        {"&anonymous", Attribute::Kind::ANONYMOUS},
        {"&internal", Attribute::Kind::INTERNAL},
        {"&optional", Attribute::Kind::OPTIONAL},
        {"&static", Attribute::Kind::STATIC},
        {"&no-emit", Attribute::Kind::NO_EMIT},
        {"&on-heap", Attribute::Kind::ON_HEAP},
        {"&nosub", Attribute::Kind::NOSUB},
        {"&cxxname", Attribute::Kind::CXXNAME},
        {"&have_prototype", Attribute::Kind::HAVE_PROTOTYPE},
        {"&priority", Attribute::Kind::PRIORITY},
        {"&convert", Attribute::Kind::CONVERT},
        {"&while", Attribute::Kind::WHILE},
        {"&requires", Attribute::Kind::REQUIRES},
        {"&byte-order", Attribute::Kind::BYTE_ORDER_},
        {"&bit-order", Attribute::Kind::BIT_ORDER},
        {"&chunked", Attribute::Kind::CHUNKED},
        {"&originator", Attribute::Kind::ORIGINATOR},
        {"&responder", Attribute::Kind::RESPONDER},
        {"&try", Attribute::Kind::TRY},
        {"&needed-by-feature", Attribute::Kind::NEEDED_BY_FEATURE},
        {"&requires-type-feature", Attribute::Kind::REQUIRES_TYPE_FEATURE},
        {"&always-emit", Attribute::Kind::ALWAYS_EMIT},
        {"&transient", Attribute::Kind::TRANSIENT},
        {"&anchor", Attribute::Kind::ANCHOR},
        {"%debug", Attribute::Kind::DEBUG},
        {"%error", Attribute::Kind::ERROR},
        {"foreach", Attribute::Kind::FOREACH},
    };
};

/** AST node holding a set of `Attribute` nodes. */
class AttributeSet : public Node {
public:
    /** Returns the set's attributes. */
    auto attributes() const { return children<Attribute>(0, {}); }

    /**
     * Retrieves an attribute with a given kind from the set. If multiple
     * attributes with that kind exist, it's undefined which one is returned.
     *
     * @return attribute if found
     */
    Attribute* find(Attribute::Kind kind) const;

    /**
     * Retrieves all attributes with a given kind from the set.
     *
     * @return all attributes with matching kind
     */
    hilti::node::Set<Attribute> findAll(Attribute::Kind kind) const;

    /**
     * Returns true if there's an attribute with a given kind in the set.
     *
     * @param true if found
     */
    bool has(Attribute::Kind kind) const { return find(kind) != nullptr; }

    /** Adds an attribute to the set. */
    void add(ASTContext* ctx, Attribute* a) {
        addChild(ctx, a);
        // Combine this location with the attribute's location so this spans the range
        setMeta(meta().mergeLocation(a->location()));
    }

    /** Removes all attributes of the given kind. */
    void remove(Attribute::Kind kind);

    /** Returns true if the set has at least one element. */
    operator bool() const { return ! attributes().empty(); }

    static auto create(ASTContext* ctx, Attributes attrs = {}, Meta m = Meta()) {
        return ctx->make<AttributeSet>(ctx, std::move(attrs), std::move(m));
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
