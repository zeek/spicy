// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a struct type. */
class Union : public TypeBase {
public:
    Union(std::vector<Declaration> fields, Meta m = Meta())
        : TypeBase(nodes(node::none, std::move(fields)), std::move(m)) {}
    Union(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(nodes(node::none), std::move(m)), _wildcard(true) {}

    auto fields() const { return childrenOfType<declaration::Field>(); }

    hilti::optional_ref<const declaration::Field> field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                return f;
        }

        return {};
    }

    unsigned int index(const ID& id) const {
        for ( const auto&& [i, f] : util::enumerate(fields()) ) {
            if ( f.id() == id )
                return i + 1;
        }

        return 0;
    }

    bool operator==(const Union& other) const { return fields() == other.fields(); }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }

    bool _isResolved(ResolvedState* rstate) const override {
        for ( auto c = ++children().begin(); c != children().end(); c++ ) {
            if ( ! c->as<declaration::Field>().isResolved(rstate) )
                return false;
        }

        return true;
    }

    std::vector<Node> typeParameters() const override {
        std::vector<Node> params;
        for ( auto c = ++children().begin(); c != children().end(); c++ )
            params.emplace_back(c->as<declaration::Field>().type());
        return params;
    }

    bool isWildcard() const override { return _wildcard; }

    node::Properties properties() const override { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isParameterized() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    /**
     * Copies an existing type and adds a new field to the copy.
     *
     * @param s original type
     * @param f field to add
     * @return new typed with field added
     */
    static Union addField(const Union& s, declaration::Field f) {
        auto x = Type(s)._clone().as<Union>();
        x.addChild(std::move(f));
        return x;
    }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
