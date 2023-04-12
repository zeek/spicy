// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <functional>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/grouping.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/operators/reference.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a struct type. */
class Struct : public TypeBase, trait::isAllocable, trait::isParameterized, trait::takesArguments, trait::isMutable {
public:
    Struct(std::vector<Declaration> fields, Meta m = Meta())
        : TypeBase(nodes(node::none, std::move(fields)), std::move(m)) {}

    struct AnonymousStruct {};
    Struct(AnonymousStruct _, std::vector<Declaration> fields, Meta m = Meta())
        : TypeBase(nodes(node::none, std::move(fields)), std::move(m)), _anon_struct(++_anon_struct_counter) {}

    Struct(const std::vector<type::function::Parameter>& params, std::vector<Declaration> fields, Meta m = Meta())
        : TypeBase(nodes(node::none, std::move(fields),
                         util::transform(params,
                                         [](auto p) {
                                             p.setIsTypeParameter();
                                             return Declaration(p);
                                         })),
                   std::move(m)) {}

    Struct(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(nodes(node::none), std::move(m)), _wildcard(true) {}

    NodeRef selfRef() const {
        if ( children()[0].isA<Declaration>() )
            return NodeRef(children()[0]);
        else
            return {};
    }

    auto hasFinalizer() const { return field("~finally").has_value(); }
    auto parameters() const { return childrenOfType<type::function::Parameter>(); }
    auto parameterRefs() const { return childRefsOfType<type::function::Parameter>(); }

    auto fields() const { return childrenOfType<declaration::Field>(); }

    hilti::optional_ref<const declaration::Field> field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                return f;
        }

        return {};
    }

    hilti::node::Set<declaration::Field> fields(const ID& id) const {
        hilti::node::Set<declaration::Field> x;
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                x.insert(f);
        }

        return x;
    }

    void addField(Declaration f) {
        assert(f.isA<declaration::Field>());
        addChild(std::move(f));
    }

    bool operator==(const Struct& other) const { return fields() == other.fields(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const {
        if ( auto x = other.tryAs<type::Struct>() ) {
            // Anonymous structs only compare successfully to themselves.
            if ( _anon_struct >= 0 || x->_anon_struct >= 0 )
                return _anon_struct == x->_anon_struct;
        }

        return node::isEqual(this, other);
    }

    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        const auto& cs = children();

        return std::all_of(cs.begin(), cs.end(), [&](const auto& c) {
            if ( auto f = c.template tryAs<declaration::Field>() )
                return f->isResolved(rstate);

            else if ( auto p = c.template tryAs<type::function::Parameter>() )
                return p->isResolved(rstate);

            return true;
        });
    }

    /** Implements the `Type` interface. */
    auto typeParameters() const {
        std::vector<Node> params;
        for ( const auto& f : fields() )
            params.emplace_back(f.type());
        return params;
    }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Given an existing node wrapping a struct type, updates the contained
     * struct type to have its `self` declaration initialized. The struct
     * type's constructor cannot do this because we need the `Node` shell for
     * this.
     */
    static void setSelf(Node* n) {
        assert(n->isA<type::Struct>());
        Expression self =
            expression::Keyword(expression::keyword::Kind::Self, type::ValueReference(NodeRef(*n)), n->meta());
        Declaration d = declaration::Expression("self", std::move(self), declaration::Linkage::Private, n->meta());
        n->children()[0] = d;
    }

private:
    bool _wildcard = false;
    int64_t _anon_struct = -1;

    static int64_t _anon_struct_counter;
};

} // namespace hilti::type
