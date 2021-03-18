// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <optional>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace type {

namespace struct_ {
/** AST node for a struct field. */
class Field : public NodeBase {
public:
    Field() : NodeBase({ID("<no id>"), type::unknown, node::none, node::none}, Meta()) {}
    Field(ID id, Type t, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(t), node::none, std::move(attrs), node::none), std::move(m)) {}
    Field(ID id, Type t, Type aux_type, std::optional<AttributeSet> attrs, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(t), std::move(aux_type), std::move(attrs), node::none),
                   std::move(m)) {}
    Field(ID id, ::hilti::function::CallingConvention cc, type::Function ft, std::optional<AttributeSet> attrs = {},
          Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(ft), node::none, std::move(attrs), node::none), std::move(m)),
          _cc(cc) {}
    Field(ID id, hilti::Function inline_func, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(id), node::none, node::none, std::move(attrs), std::move(inline_func)),
                   std::move(m)),
          _cc(inline_func.callingConvention()) {}

    const auto& id() const { return child<ID>(0); }

    auto callingConvention() const { return _cc; }
    auto inlineFunction() const { return childs()[4].tryReferenceAs<hilti::Function>(); }
    auto attributes() const { return childs()[3].tryReferenceAs<AttributeSet>(); }

    Type type() const {
        if ( ! _cache.type ) {
            if ( auto func = inlineFunction() )
                _cache.type = func->type();
            else
                _cache.type = type::effectiveType(child<Type>(1));
        }

        return *_cache.type;
    }

    /**
     * Returns the auxiliary type as passed into the corresponding
     * constructor, if any. The auxiliary type isn't used for anything by
     * HILTI itself, but it's as a node in aside the AST for use by external
     * code.
     */
    std::optional<Type> auxType() const {
        if ( auto t = childs()[2].tryAs<Type>() )
            return type::effectiveType(*t);
        else
            return {};
    }

    std::optional<Expression> default_() const {
        if ( auto a = AttributeSet::find(attributes(), "&default") )
            return *a->valueAs<Expression>();

        return {};
    }

    auto isInternal() const { return AttributeSet::find(attributes(), "&internal").has_value(); }
    auto isOptional() const { return AttributeSet::find(attributes(), "&optional").has_value(); }
    auto isStatic() const { return AttributeSet::find(attributes(), "&static").has_value(); }
    auto isNoEmit() const { return AttributeSet::find(attributes(), "&no-emit").has_value(); }

    /** Internal method for use by builder API only. */
    auto& _typeNode() { return childs()[1]; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"cc", to_string(_cc)}}; }

    bool operator==(const Field& other) const {
        return id() == other.id() && type() == other.type() && attributes() == other.attributes() && _cc == other._cc;
    }

    /**
     * Copies an existing field but replaces its attributes.
     *
     * @param f original field
     * @param attrs new attributes
     * @return new field with attributes replaced
     */
    static Field setAttributes(const Field& f, const AttributeSet& attrs) {
        auto x = Field(f);
        x.childs()[3] = attrs;
        return x;
    }

    void clearCache() { _cache.type.reset(); }

private:
    ::hilti::function::CallingConvention _cc = ::hilti::function::CallingConvention::Standard;

    mutable struct { std::optional<Type> type; } _cache;
}; // namespace struct_

inline Node to_node(Field f) { return Node(std::move(f)); }

} // namespace struct_

/** AST node for a struct type. */
class Struct : public TypeBase, trait::isAllocable, trait::isParameterized, trait::isMutable {
public:
    Struct(std::vector<struct_::Field> fields, Meta m = Meta())
        : TypeBase(nodes(node::none, std::move(fields)), std::move(m)) {
        _state().flags += type::Flag::NoInheritScope;
    }

    Struct(std::vector<type::function::Parameter> params, std::vector<struct_::Field> fields, Meta m = Meta())
        : TypeBase(nodes(node::none, std::move(fields),
                         util::transform(params,
                                         [](const auto& p) {
                                             return type::function::Parameter::setIsStructParameter(p);
                                         })),
                   std::move(m)) {
        _state().flags += type::Flag::NoInheritScope;
    }

    Struct(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(nodes(node::none), std::move(m)), _wildcard(true) {
        _state().flags += type::Flag::NoInheritScope;
    }

    auto hasFinalizer() const { return field("~finally").has_value(); }

    auto parameters() const { return childsOfType<type::function::Parameter>(); }

    std::vector<NodeRef> parameterNodes() {
        std::vector<NodeRef> params;
        for ( auto& c : childs() ) {
            if ( c.isA<type::function::Parameter>() )
                params.emplace_back(NodeRef(c));
        }
        return params;
    }

    auto fields() const { return childsOfType<struct_::Field>(); }

    auto types() const {
        std::vector<Type> types;
        for ( auto c = ++childs().begin(); c != childs().end(); c++ )
            types.push_back(c->as<struct_::Field>().type());

        return types;
    }

    auto ids() const {
        std::vector<ID> ids;
        for ( auto c = ++childs().begin(); c != childs().end(); c++ )
            ids.push_back(c->as<struct_::Field>().id());

        return ids;
    }

    std::optional<struct_::Field> field(const ID& id) const {
        for ( auto f : fields() ) {
            if ( f.id() == id )
                return f;
        }

        return {};
    }

    auto fields(const ID& id) const {
        std::vector<struct_::Field> x;

        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                x.push_back(f);
        }

        return x;
    }

    bool operator==(const Struct& other) const {
        if ( typeID() && other.typeID() )
            return *typeID() == *other.typeID();

        return fields() == other.fields();
    }

    /** For internal use by the builder API only. */
    auto _fieldNodes() { return nodesOfType<struct_::Field>(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto typeParameters() const {
        std::vector<Node> params;
        for ( auto c = ++childs().begin(); c != childs().end(); c++ )
            params.emplace_back(c->as<struct_::Field>().type());
        return params;
    }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Copies an existing type and adds a new field to the copy.
     *
     * @param s original type
     * @param f field to add
     * @return new typed with field added
     */
    static Struct addField(const Struct& s, struct_::Field f) {
        auto x = Type(s)._clone().as<Struct>();
        x.addChild(std::move(f));
        return x;
    }

private:
    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
