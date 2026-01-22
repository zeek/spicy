// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>
#include <hilti/base/util.h>

namespace hilti {

namespace attribute {

/**
 * Represents a specific attribute. While we generally identify attributes by
 * their names (`&...`), we wrap those strings into `Kind` instances so that we
 * can (1) define global constants for all valid attribute names, and (2)
 * retain a list of all known attributes for error checking.
 *
 * Note that generally, one should only use the global, pre-defined constants
 * when referring to a specific attribute. Avoid creating new instances on the
 * fly.
 */
class Kind {
public:
    explicit Kind(std::string name) : _name(std::move(name)) { _register(); }

    Kind() = delete;
    Kind(const Kind& other) = default;
    Kind(Kind&& other) = default;

    ~Kind() = default; // not unregistering here, so that attribute remains known

    operator std::string() const { return _name; }

    Kind& operator=(const Kind& other) = default;
    Kind& operator=(Kind&& other) = default;

    bool operator==(const Kind& other) const { return _name == other._name; }
    bool operator!=(const Kind& other) const { return ! operator==(other); }

    // Returns a corresponding attribute kind iff the string matches to one of
    // the known attributes created so far. Otherwise throws an `out_of_range`
    // exception.
    static Kind fromString(const std::string_view& s) {
        if ( _known_attributes && _known_attributes->contains(std::string(s)) )
            return Kind(std::string(s));
        else
            throw std::out_of_range("unknown attribute kind: " + std::string(s));
    }

private:
    void _register();

    std::string _name = "<unset attribute>";
    static std::set<std::string>* _known_attributes;
};

/** Returns whether `kind` is in `kinds` */
inline bool isOneOf(const Kind& kind, std::initializer_list<Kind> kinds) {
    return std::ranges::find(kinds, kind) != kinds.end();
}

inline auto to_string(const Kind& kind) { return std::string(kind); }

inline std::ostream& operator<<(std::ostream& out, const Kind& x) {
    out << to_string(x);
    return out;
}

namespace kind {
inline auto from_string(const std::string_view& s) { return Kind::fromString(s); }

// In the following, we predefine all attributes that are part of the HILTI language.

const Kind AlwaysEmit("&always-emit");
const Kind Anchor("&anchor");
const Kind Anonymous("&anonymous");
const Kind Convert("&convert");
const Kind Cxxname("&cxxname");
const Kind CxxAnyAsPtr("&cxx-any-as-ptr");
const Kind Debug("&debug");
const Kind Default("&default");
const Kind HavePrototype("&have_prototype");
const Kind Internal("&internal");
const Kind NeededByFeature("&needed-by-feature");
const Kind NoEmit("&no-emit");
const Kind Nosub("&nosub");
const Kind OnHeap("&on-heap");
const Kind Optional("&optional");
const Kind Priority("&priority");
const Kind Public("&public");
const Kind RequiresTypeFeature("&requires-type-feature");
const Kind Static("&static");

} // namespace kind
} // namespace attribute

/** AST node for an attribute. */
class Attribute : public Node {
public:
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

    node::Properties properties() const final {
        auto p = node::Properties{{"tag", to_string(kind())}};
        return Node::properties() + std::move(p);
    }

    /**
     * Factory for an attribute coming with an argument. The argument must be
     * an AST node representing an expression.
     *
     * @param kind the attribute's internal representation
     * @param v node representing the argument to associate with the attribute; must be an expression
     * @param m meta data to associate with the node
     */
    static auto create(ASTContext* ctx, const attribute::Kind& kind, Expression* v, const Meta& m = Meta()) {
        return ctx->make<Attribute>(ctx, {v}, kind, m);
    }

    /**
     * Factory for an attribute with no argument.
     *
     * @param kind the attribute's internal representation
     * @param m meta data to associate with the node
     */
    static auto create(ASTContext* ctx, const attribute::Kind& kind, const Meta& m = Meta()) {
        return create(ctx, kind, nullptr, m);
    }

protected:
    Attribute(ASTContext* ctx, Nodes children, attribute::Kind kind, Meta m = Meta())
        : Node(ctx, NodeTags, std::move(children), std::move(m)), _kind(std::move(kind)) {}

    std::string _dump() const override;

    HILTI_NODE_0(Attribute, final);

private:
    attribute::Kind _kind;
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
     * @return attribute if found, or null otherwise.
     */
    Attribute* find(const attribute::Kind& kind) const;

    /**
     * Retrieves all attributes with a given kind from the set.
     *
     * @return all attributes with matching kind
     */
    hilti::node::Set<Attribute> findAll(const attribute::Kind& kind) const;

    /** Adds an attribute to the set. */
    void add(ASTContext* ctx, Attribute* a) {
        addChild(ctx, a);
        // Combine this location with the attribute's location so this spans the range
        setMeta(meta().mergeLocation(a->location()));
    }

    /** Removes all attributes of the given kind. */
    void remove(const attribute::Kind& kind);

    /** Removes a specific attribute from the set. */
    void remove(Attribute* a) { removeChild(a); }

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

namespace std {
template<>
struct hash<hilti::attribute::Kind> {
    size_t operator()(const hilti::attribute::Kind& x) const { return std::hash<std::string>()(x); }
};
} // namespace std
