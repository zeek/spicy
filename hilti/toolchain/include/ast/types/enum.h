// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/type.h>

namespace hilti {
namespace type {

namespace enum_ {
/** AST node for an enum label. */
class Label : public NodeBase, public util::type_erasure::trait::Singleton {
public:
    Label() : NodeBase({ID("<no id>")}, Meta()) {}
    Label(ID id, Meta m = Meta()) : NodeBase({std::move(id)}, std::move(m)) {}
    Label(ID id, int v, Meta m = Meta()) : NodeBase({std::move(id)}, std::move(m)), _value(v) {}

    auto id() const { return child<ID>(0); }
    auto value() const { return _value; }

    bool operator==(const Label& other) const { return id() == other.id() && value() == other.value(); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"value", _value}}; }

private:
    int _value = -1;
};

inline Node to_node(Label l) { return Node(std::move(l)); }

} // namespace enum_

/** AST node for an enum type. */
class Enum : public TypeBase, trait::isAllocable, trait::isParameterized {
public:
    Enum(std::vector<enum_::Label> l, Meta m = Meta())
        : TypeBase(nodes(_normalizeLabels(std::move(l))), std::move(m)) {}
    Enum(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {}

    std::vector<enum_::Label> labels() const { return childs<enum_::Label>(0, -1); }

    /**
     * Returns the set of labels but makes sure to include each enumator
     * value at most once.
     */
    std::vector<enum_::Label> uniqueLabels() const {
        auto pred_gt = [](const enum_::Label& e1, const enum_::Label& e2) { return e1.value() > e2.value(); };
        auto pred_eq = [](const enum_::Label& e1, const enum_::Label& e2) { return e1.value() == e2.value(); };
        std::vector<enum_::Label> x = labels();
        std::sort(x.begin(), x.end(), pred_gt);
        x.erase(std::unique(x.begin(), x.end(), pred_eq), x.end());
        return x;
    }

    std::optional<enum_::Label> label(const ID& id) const {
        for ( auto l : labels() ) {
            if ( l.id() == id )
                return l;
        }

        return {};
    }

    bool operator==(const Enum& other) const {
        if ( typeID() && other.typeID() )
            return *typeID() == *other.typeID();

        return labels() == other.labels();
    }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto typeParameters() const {
        std::vector<Node> params;
        for ( auto&& c : uniqueLabels() )
            params.emplace_back(std::move(c));
        return params;
    }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    static std::vector<enum_::Label> _normalizeLabels(std::vector<enum_::Label> /*labels*/);

    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
