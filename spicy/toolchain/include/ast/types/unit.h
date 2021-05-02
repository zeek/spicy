// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expressions/grouping.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/type.h>
#include <hilti/ast/types/reference.h>

#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/property.h>
#include <spicy/ast/types/unit-items/switch.h>
#include <spicy/ast/types/unit-items/unresolved-field.h>
#include <spicy/compiler/detail/codegen/grammar.h>

namespace spicy {

namespace detail::codegen {
class Grammar;
} // namespace detail::codegen

namespace type {

namespace detail {
/**
 * Mixin class to number all fields in sequential order.
 *
 * This functionality is not implemented in `Unit` since we want to use
 * `assignIndices` in a call to a base class's constructor before `Unit` is
 * fully constructed. Putting the counter `_next_index` into `Unit` would lead
 * to it being initialized after `Unit`'s base class `TypeBase`.
 */
struct AssignIndices {
    /**
     * Helper function to recursively number all fields in the passed list in sequential order
     *
     * @param items the items to number
     * @return a pair of mutated items and the next index
     */
    std::vector<unit::Item> assignIndices(std::vector<unit::Item> items);

    uint64_t _next_index = 0;
};
} // namespace detail

/** AST node for a Spicy unit. */
class Unit : detail::AssignIndices,
             public hilti::TypeBase,
             hilti::type::trait::isAllocable,
             hilti::type::trait::isParameterized,
             hilti::type::trait::takesArguments,
             hilti::type::trait::isMutable {
public:
    Unit(std::vector<type::function::Parameter> params, std::vector<unit::Item> i,
         const std::optional<AttributeSet>& /* attrs */ = {}, Meta m = Meta())
        : TypeBase(hilti::nodes(node::none, node::none, node::none,
                                hilti::util::transform(params,
                                                       [](auto p) {
                                                           p.setIsTypeParameter();
                                                           return Declaration(p);
                                                       }),
                                assignIndices(std::move(i))),
                   std::move(m)) {}

    Unit(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {}

    NodeRef selfRef() const {
        if ( childs()[0].isA<Declaration>() )
            return NodeRef(childs()[0]);
        else
            return {};
    }

    auto id() const { return childs()[1].tryAs<ID>(); }
    auto parameters() const { return childsOfType<type::function::Parameter>(); }
    auto parameterRefs() const { return childRefsOfType<type::function::Parameter>(); }
    auto items() const { return childsOfType<unit::Item>(); }
    auto itemRefs() const { return childRefsOfType<unit::Item>(); }
    auto attributes() const { return childs()[2].tryAs<AttributeSet>(); }

    /** Returns the type set through ``%context`, if available. */
    hilti::optional_ref<const Type> contextType() const {
        if ( auto context = propertyItem("%context") )
            return context->expression()->as<hilti::expression::Type_>().typeValue();
        else
            return {};
    }

    /**
     * Returns the item of a given name if it exists. This descends
     * recursively into childs as well.
     */
    hilti::optional_ref<const type::unit::Item> itemByName(const ID& id) const;

    /** Returns a reference to an item give by its ID. */
    NodeRef itemRefByName(const ID& id) const;

    /**
     * Returns all of the unit's items of a particular subtype T.
     **/
    template<typename T>
    auto items() const {
        return childsOfType<T>();
    }

    /**
     * Returns the property of a given name if it exists. If it exists more
     * than once, it's undefined which one is returned.
     */
    hilti::optional_ref<const unit::item::Property> propertyItem(const std::string& name) const {
        for ( const auto& i : items<unit::item::Property>() ) {
            if ( i.id() == name )
                return i;
        }

        return {};
    }

    /** Returns all properties of a given name. */
    auto propertyItems(const std::string& name) const {
        hilti::node::Set<unit::item::Property> props;

        for ( const auto& i : items<unit::item::Property>() ) {
            if ( i.id() == name )
                props.insert(i);
        }

        return props;
    }

    /**
     * Returns true if the unit has been declared as publically/externally
     * accessible.
     */
    auto isPublic() const { return _public; };

    /**
     * Returns true if for this unit the parser generator needs to generate
     * code facilitating random access within the data that an instance is
     * being parsed from.
     *
     * \todo Currently this feature gets enabled through an attribute
     * (`%random-access`). Eventually we should enable this automatically as
     * needed, through static analysis.
     */
    bool usesRandomAccess() const { return propertyItem("%random-access").has_value(); }

    /**
     * Returns true if this unit type supports connecting to a sink.
     *
     * \todo Currently we tie this capability to unit types being public,
     * which is just a hack until we get something better. Eventually we
     * should support this automatically as needed, through static analysis.
     */
    bool supportsSinks() const { return isPublic(); }

    /**
     * Returns true if this unit type supports connecting a filter.
     *
     * \todo Currently we tie this capability to unit types being public,
     * which is just a hack until we get something better. Eventually we
     * should support this automatically as needed, through static analysis.
     */
    bool supportsFilters() const { return isPublic(); }

    /**
     * Returns true if this unit type can act as a filter.
     *
     * \todo Currently we tie this capability to unit types being public,
     * which is just a hack until we get something better. Eventually we
     * should support this automatically as needed, through static analysis.
     */
    bool isFilter() const { return propertyItem("%filter").has_value(); }

    /** Returns the grammar associated with the type. It must have been set
     * before through `setGrammar()`. */
    const spicy::detail::codegen::Grammar& grammar() const {
        assert(_grammar);
        return *_grammar;
    }

    /** Adds a number of new items to the unit. */
    void addItems(std::vector<unit::Item> items) {
        auto new_items = assignIndices(items);

        for ( auto i : new_items )
            childs().emplace_back(std::move(i));
    }

    void setAttributes(AttributeSet attrs) { childs()[2] = std::move(attrs); }
    void setGrammar(std::shared_ptr<spicy::detail::codegen::Grammar> g) { _grammar = std::move(g); }
    void setID(ID id) { childs()[1] = std::move(id); }
    void setPublic(bool p) { _public = p; }

    bool operator==(const Unit& other) const {
        // We treat units as equal (only) if their type IDs match. That's
        // checked upstream in the Type's comparision operator.
        return false;
    }

    // Type interface.
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }

    auto _isResolved(ResolvedState* rstate) const {
        for ( const auto& i : items() ) {
            if ( ! i.isResolved() )
                return false;
        }

        return true;
    }

    // type::trait::Parameterized interface.
    auto typeParameters() const { return childs(); }
    auto isWildcard() const { return _wildcard; }

    // Node interface.
    auto properties() const { return node::Properties{{"public", _public}}; }

    /**
     * Given an existing node wrapping a unit type, updates the contained unit
     * type to have its `self` declaration initialized. Note that the unit
     * type's constructor cannot do this because we need the `Node` shell for
     * this.
     */
    static void setSelf(Node* n) {
        assert(n->isA<type::Unit>());
        Expression self = hilti::expression::Keyword(hilti::expression::keyword::Kind::Self,
                                                     StrongReference(hilti::type::pruneWalk(n->as<Type>())), n->meta());
        Declaration d =
            hilti::declaration::Expression("self", std::move(self), declaration::Linkage::Private, n->meta());
        n->childs()[0] = std::move(d);
    }

private:
    bool _public = false;
    bool _wildcard = false;
    std::shared_ptr<spicy::detail::codegen::Grammar> _grammar;
};


} // namespace type
} // namespace spicy
