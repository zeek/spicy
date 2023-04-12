// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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
class Union : public TypeBase, trait::isAllocable, trait::isParameterized, trait::isMutable {
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

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }

    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        for ( auto c = ++children().begin(); c != children().end(); c++ ) {
            if ( ! c->as<declaration::Field>().isResolved(rstate) )
                return false;
        }

        return true;
    }

    /** Implements the `Type` interface. */
    auto typeParameters() const {
        std::vector<Node> params;
        for ( auto c = ++children().begin(); c != children().end(); c++ )
            params.emplace_back(c->as<declaration::Field>().type());
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
    static Union addField(const Union& s, declaration::Field f) {
        auto x = Type(s)._clone().as<Union>();
        x.addChild(std::move(f));
        return x;
    }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
