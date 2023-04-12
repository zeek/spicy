// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <set>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace enum_ {
/** AST node for an enum label. */
class Label : public NodeBase, public util::type_erasure::trait::Singleton {
public:
    Label() : NodeBase({ID("<no id>")}, Meta()) {}
    Label(ID id, Meta m = Meta()) : NodeBase(nodes(std::move(id)), std::move(m)) {}
    Label(ID id, int v, Meta m = Meta()) : NodeBase(nodes(std::move(id)), std::move(m)), _value(v) {}

    // Recreate from an existing label, but setting type.
    Label(const Label& other, NodeRef enum_type)
        : NodeBase(nodes(other.id()), other.meta()), _etype(std::move(enum_type)), _value(other._value) {}

    const ID& id() const { return child<ID>(0); }
    const auto& enumType() const { return _etype ? _etype->as<Type>() : type::auto_; }
    auto value() const { return _value; }

    bool operator==(const Label& other) const { return id() == other.id() && value() == other.value(); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"value", _value}, {"etype", _etype.rid()}}; }

private:
    NodeRef _etype;
    int _value = -1;
};

inline Node to_node(Label l) { return Node(std::move(l)); }

} // namespace enum_

/** AST node for an enum type. */
class Enum : public TypeBase, trait::isAllocable, trait::isParameterized, trait::isSortable {
public:
    Enum(std::vector<enum_::Label> l, Meta m = Meta())
        : TypeBase(nodes(_normalizeLabels(std::move(l))), std::move(m)) {}
    Enum(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {}

    std::vector<std::reference_wrapper<const enum_::Label>> labels() const;

    /**
     * Filters a set of labels so that it includes each enumator value at most
     * once.
     */
    std::vector<std::reference_wrapper<const enum_::Label>> uniqueLabels() const;

    hilti::optional_ref<const enum_::Label> label(const ID& id) const {
        for ( const auto& l : labels() ) {
            if ( l.get().id() == id )
                return l.get();
        }

        return {};
    }

    auto labelDeclarationRefs() { return childRefs(0, -1); }

    bool operator==(const Enum& other) const {
        return children<Declaration>(0, -1) == other.children<Declaration>(0, -1);
    }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return _initialized; }
    /** Implements the `Type` interface. */
    auto typeParameters() const {
        std::vector<Node> params;
        for ( auto&& c : uniqueLabels() )
            params.emplace_back(c.get());

        return params;
    }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /** Helper method for the resolver to link labels to their type. */
    static void initLabelTypes(Node* n);

private:
    static std::vector<Declaration> _normalizeLabels(std::vector<enum_::Label> labels);

    bool _wildcard = false;
    bool _initialized = false;
};

} // namespace hilti::type
