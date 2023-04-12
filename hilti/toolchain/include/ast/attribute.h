// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/ctors/string.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/node.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/util.h>
#include <hilti/compiler/coercion.h>
#include <hilti/global.h>

namespace hilti {

/** AST node captures an `&<tag>` attribute along with an optional argument. */
class Attribute : public NodeBase {
public:
    Attribute() = default;

    /**
     * Constructor for an attribute with no argument.
     *
     * @param tag name of the attribute, including the leading `&`
     * @param m meta data to associate with the node
     */
    Attribute(std::string tag, Meta m = Meta()) : NodeBase({node::none}, std::move(m)), _tag(std::move(tag)) {}

    /**
     * Constructor for an attribute coming with an argument. The argument
     * must be either an AST node representing an expression.
     *
     * @param tag name of the attribute, including the leading `&`
     * @param v node representing the argument to associate with the attribute; must be an expression
     * @param m meta data to associate with the node
     */
    Attribute(std::string tag, Node v, Meta m = Meta())
        : NodeBase({std::move(v)}, std::move(m)), _tag(std::move(tag)) {}

    /** Returns the name of the attribute, including the leading `&`. */
    const auto& tag() const { return _tag; }

    /** Returns true if an argument is associated with the attribute. */
    bool hasValue() const { return ! children()[0].isA<node::None>(); }

    /**
     * Returns the attribute associated with the node.
     *
     * @exception `std::out_of_range` if the attribute does not have an argument
     */
    const Node& value() const { return children()[0]; }

    /**
     * Returns the attributes argument as type `T`. `T` must be either an
     * `Expression`, or `std::string`. In the former case, the value must be
     * an AST expression node. In the latter case, the argument must be a
     * string constructor expression, and the returned value will be the
     * string it represents.
     *
     * @tparam T either `Expression` or `std::string`
     * @return the argument, or an error if the argument could not be interpreted as type `T`
     * @exception `std::out_of_range` if the attribute does not have an argument
     */
    Result<std::reference_wrapper<const Expression>> valueAsExpression() const {
        if ( ! hasValue() )
            return result::Error(hilti::util::fmt("attribute '%s' requires an expression", _tag));

        if ( ! value().isA<Expression>() )
            return result::Error(hilti::util::fmt("value for attribute '%s' must be an expression", _tag));

        return {value().as<Expression>()};
    }

    Result<std::string> valueAsString() const {
        if ( ! hasValue() )
            return result::Error(hilti::util::fmt("attribute '%s' requires a string", _tag));

        if ( auto e = value().tryAs<expression::Ctor>() )
            if ( auto s = e->ctor().tryAs<ctor::String>() )
                return s->value();

        return result::Error(hilti::util::fmt("value for attribute '%s' must be a string", _tag));
    }

    Result<int64_t> valueAsInteger() const {
        if ( ! hasValue() )
            return result::Error(hilti::util::fmt("attribute '%s' requires an integer", _tag));

        if ( auto e = value().tryAs<expression::Ctor>() ) {
            if ( auto s = e->ctor().tryAs<ctor::SignedInteger>() )
                return s->value();

            if ( auto s = e->ctor().tryAs<ctor::UnsignedInteger>() )
                return static_cast<int64_t>(s->value());
        }

        return result::Error(hilti::util::fmt("value for attribute '%s' must be an integer", _tag));
    }

    /**
     * Coerce the attribute's expression value to a specified type.
     *
     * @return A successful return value if either the coercion succeeded
     * (then the result's value is true), or nothing was to be done (then the
     * result's value is false); a failure if a coercion would have been
     * necessary, but failed, or the attribute does not have a expression value.
     */
    Result<bool> coerceValueTo(const Type& dst) {
        auto x = valueAsExpression();
        if ( ! x )
            return x.error();

        if ( ! type::isResolved(dst) )
            return false;

        auto ne = coerceExpression(*x, dst);
        if ( ! ne.coerced )
            return result::Error(util::fmt("cannot coerce attribute's expression from type '%s' to '%s' (%s)",
                                           x->get().type(), dst, tag()));

        if ( ne.nexpr ) {
            children()[0] = *ne.nexpr;
            return true;
        }

        return false;
    }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"tag", _tag}}; }

    bool operator==(const Attribute& other) const {
        if ( _tag != other._tag )
            return false;

        if ( auto x = valueAsExpression() ) {
            auto y = other.valueAsExpression();
            return y && *x == *y;
        }

        else if ( auto x = valueAsString() ) {
            auto y = other.valueAsString();
            return y && *x == *y;
        }

        else if ( auto x = valueAsInteger() ) {
            auto y = other.valueAsInteger();
            return y && *x == *y;
        }

        return false;
    }

private:
    std::string _tag;
};

/**
 * Constructs an AST node from an attribute.
 */
inline Node to_node(Attribute i) { return Node(std::move(i)); }

/** AST node holding a set of `Attribute` nodes. */
class AttributeSet : public NodeBase {
public:
    /**
     * Constructs a set from from a vector of attributes.
     *
     * @param a vector to initialize attribute set from
     * @param m meta data to associate with the node
     */
    explicit AttributeSet(std::vector<Attribute> a, Meta m = Meta()) : NodeBase(nodes(std::move(a)), std::move(m)) {}

    /**
     * Constructs an empty set.
     *
     * @param m meta data to associate with the node
     */
    AttributeSet(Meta m = Meta()) : NodeBase({}, std::move(m)) {}

    /** Returns the set's attributes. */
    auto attributes() const { return children<Attribute>(0, -1); }

    /**
     * Retrieves an attribute with a given name from the set. If multiple
     * attributes with that tag exist, it's undefined which is returned.
     *
     * @return attribute if found
     */
    hilti::optional_ref<const Attribute> find(std::string_view tag) const {
        for ( const auto& a : attributes() )
            if ( a.tag() == tag )
                return a;

        return {};
    }

    /**
     * Retrieves all attributes with a given name from the set.
     *
     * @return all attributes with matching name
     */
    auto findAll(std::string_view tag) const {
        hilti::node::Set<Attribute> result;

        for ( const auto& a : attributes() )
            if ( a.tag() == tag )
                result.insert(a);

        return result;
    }

    /**
     * If an attribute of a given name exists and has an expression value,
     * the value is coerced to a specified type. If not, nothing is done.
     *
     * @return A successful return value if either the coercion succeeded
     * (then the result's value is true), or nothing was to be done (then the
     * result's value is false); a failures if a coercion would have been
     * necessary, but failed.
     */
    Result<bool> coerceValueTo(const std::string& tag, const Type& dst) {
        if ( ! type::isResolved(dst) )
            return false;

        for ( auto& n : children() ) {
            auto a = n.as<Attribute>();
            if ( a.tag() != tag )
                continue;

            if ( auto e = a.valueAsExpression() ) {
                auto ne = coerceExpression(*e, dst);
                if ( ! ne.coerced )
                    return result::Error("cannot coerce attribute value");

                if ( ne.nexpr ) {
                    n = Attribute(tag, std::move(*ne.nexpr));
                    return true;
                }

                return false;
            }
        }

        return false;
    }

    /**
     * Returns true if there's an attribute with a given name in the set.
     *
     * @param true if found
     */
    bool has(std::string_view tag) const { return find(tag).has_value(); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const AttributeSet& other) const { return attributes() == other.attributes(); };

    /** Returns true if the set has at least one element. */
    operator bool() const { return ! children().empty(); }

    /**
     * Returns a new attribute set that adds one element.
     *
     * @param s set to add to.
     * @param a element to add.
     * @return `s` with `a' added
     */
    static AttributeSet add(AttributeSet s, Attribute a) {
        s.addChild(std::move(a));
        return s;
    }

    /**
     * Returns a new attribute set that adds one element.
     *
     * @param s set to add to.
     * @param a element to add.
     * @return `s` with `a' added
     */
    static AttributeSet add(std::optional<AttributeSet> s, Attribute a) {
        if ( ! s )
            s = AttributeSet({}, a.meta());

        s->addChild(std::move(a));
        return *s;
    }

    /**
     * Retrieves an attribute with a given name from a set, dealing correctly
     * with an unset optional set. If multiple attributes with that tag
     * exist, it's undefined which is returned.
     *
     * @param attrs set to inspect
     * @return attribute if found
     */
    static hilti::optional_ref<const Attribute> find(const hilti::optional_ref<const AttributeSet>& attrs,
                                                     std::string_view tag) {
        if ( attrs )
            return attrs->find(tag);
        else
            return {};
    }

    /**
     * Retrieves all attribute with a given name from a set, dealing correctly
     * with an unset optional set.
     *
     * @param attrs set to inspect
     * @return all attributes with matching name
     */
    static hilti::node::Set<Attribute> findAll(const std::optional<const AttributeSet>& attrs, std::string_view tag) {
        if ( attrs )
            return attrs->findAll(tag);
        else
            return {};
    }

    /**
     * Retrieves all attribute with a given name from a set, dealing correctly
     * with an unset optional set.
     *
     * @param attrs set to inspect
     * @return all attributes with matching name
     */
    static hilti::node::Set<Attribute> findAll(const hilti::optional_ref<const AttributeSet>& attrs,
                                               std::string_view tag) {
        if ( attrs )
            return attrs->findAll(tag);
        else
            return {};
    }

    /**
     * Returns true if there's an attribute with a given name in a set,
     * dealing correctly with an unset optional set.
     *
     * @param attrs set to inspect
     * @param true if found
     */
    static bool has(const std::optional<AttributeSet>& attrs, std::string_view tag) {
        if ( attrs )
            return attrs->has(tag);
        else
            return false;
    }
};

/**
 * Constructs an AST node from an attribute set.
 */
inline Node to_node(AttributeSet i) { return Node(std::move(i)); }
inline Node to_node(std::optional<AttributeSet>&& i) { return i ? to_node(*i) : node::none; }

} // namespace hilti
