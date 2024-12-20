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
        Eod,
        Until,
        UntilIncluding,
        ParseAt,
        ParseFrom,
        Size,
        MaxSize,
        IPv4,
        IPv6,
        Type,
        Count,
        Synchronize,
        Default,
        Anonymous,
        Internal,
        Optional,
        Static,
        NoEmit,
        OnHeap,
        Nosub,
        Cxxname,
        HavePrototype,
        Priority,
        Convert,
        While,
        Requires,
        ByteOrder,
        BitOrder,
        Chunked,
        Originator,
        Responder,
        Try,
        NeededByFeature,
        RequiresTypeFeature,
        AlwaysEmit,
        Transient,
        Anchor,

        // Hooks
        Debug,
        Error,
        Foreach,
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
        {"&eod", Attribute::Kind::Eod},
        {"&until", Attribute::Kind::Until},
        {"&until-including", Attribute::Kind::UntilIncluding},
        {"&parse-at", Attribute::Kind::ParseAt},
        {"&parse-from", Attribute::Kind::ParseFrom},
        {"&size", Attribute::Kind::Size},
        {"&max-size", Attribute::Kind::MaxSize},
        {"&ipv4", Attribute::Kind::IPv4},
        {"&ipv6", Attribute::Kind::IPv6},
        {"&type", Attribute::Kind::Type},
        {"&count", Attribute::Kind::Count},
        {"&synchronize", Attribute::Kind::Synchronize},
        {"&default", Attribute::Kind::Default},
        {"&anonymous", Attribute::Kind::Anonymous},
        {"&internal", Attribute::Kind::Internal},
        {"&optional", Attribute::Kind::Optional},
        {"&static", Attribute::Kind::Static},
        {"&no-emit", Attribute::Kind::NoEmit},
        {"&on-heap", Attribute::Kind::OnHeap},
        {"&nosub", Attribute::Kind::Nosub},
        {"&cxxname", Attribute::Kind::Cxxname},
        {"&have_prototype", Attribute::Kind::HavePrototype},
        {"&priority", Attribute::Kind::Priority},
        {"&convert", Attribute::Kind::Convert},
        {"&while", Attribute::Kind::While},
        {"&requires", Attribute::Kind::Requires},
        {"&byte-order", Attribute::Kind::ByteOrder},
        {"&bit-order", Attribute::Kind::BitOrder},
        {"&chunked", Attribute::Kind::Chunked},
        {"&originator", Attribute::Kind::Originator},
        {"&responder", Attribute::Kind::Responder},
        {"&try", Attribute::Kind::Try},
        {"&needed-by-feature", Attribute::Kind::NeededByFeature},
        {"&requires-type-feature", Attribute::Kind::RequiresTypeFeature},
        {"&always-emit", Attribute::Kind::AlwaysEmit},
        {"&transient", Attribute::Kind::Transient},
        {"&anchor", Attribute::Kind::Anchor},
        {"%debug", Attribute::Kind::Debug},
        {"%error", Attribute::Kind::Error},
        {"foreach", Attribute::Kind::Foreach},
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

    static auto create(ASTContext* ctx, const Attributes& attrs = {}, Meta m = Meta()) {
        return ctx->make<AttributeSet>(ctx, attrs, std::move(m));
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
