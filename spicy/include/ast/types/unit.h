// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/property.h>

namespace spicy {

namespace detail::codegen {
class Grammar;
} // namespace detail::codegen

namespace type {

/** AST node for a Spicy unit. */
class Unit : public hilti::TypeBase,
             hilti::type::trait::isAllocable,
             hilti::type::trait::isParameterized,
             hilti::type::trait::isOnHeap {
public:
    Unit(std::vector<type::function::Parameter> p, std::vector<unit::Item> i,
         const std::optional<AttributeSet>& /* attrs */ = {}, Meta m = Meta())
        : TypeBase(nodes(std::move(p), std::move(i)), std::move(m)) {
        _state().flags += type::Flag::NoInheritScope;
    }

    Unit(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {
        _state().flags += type::Flag::NoInheritScope;
    }

    auto parameters() const { return childsOfType<type::function::Parameter>(); }
    auto items() const { return childsOfType<unit::Item>(); }

    std::optional<AttributeSet> attributes() const {
        auto x = childsOfType<AttributeSet>();
        if ( x.size() )
            return x[0];
        else
            return {};
    }

    auto types() const {
        std::vector<Type> types;
        for ( auto c : childs() )
            types.push_back(c.as<unit::Item>().itemType());

        return types;
    }

    /**
     * Returns the field of a given name if it exists. This descends
     * recursively into childs as well.
     */
    std::optional<unit::Item> field(const ID& id) const;

#if 0
    /** Returns all items of a given name. */
    std::vector<unit::Item> items(std::string) const;

    /** Returns all items of a given name. */
    std::vector<unit::Item> items(ID id) const;
#endif
    /**
     * Returns all of the unit's items of a particular subtype T.
     **/
    template<typename T>
    auto items() const {
        std::vector<T> v;
        for ( const auto& c : childs() ) {
            if ( auto x = c.tryAs<T>() )
                v.push_back(*x);
        }
        return v;
    }

    /**
     * Returns the property of a given name if it exists. If it exists more
     * than once, it's undefined which one is returned.
     */
    std::optional<unit::item::Property> propertyItem(const std::string& name) const {
        for ( auto i : items<unit::item::Property>() ) {
            if ( i.id() == name )
                return i;
        }

        return {};
    }

    /**
     * Returns all properties of a given name.
     */
    auto propertyItems(const std::string& name) const {
        std::vector<unit::item::Property> props;

        for ( const auto& i : items<unit::item::Property>() ) {
            if ( i.id() == name )
                props.push_back(i);
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

    /** Returns the grammar associated with the type. It must have been set before through `setGrammar()`. */
    const detail::codegen::Grammar& grammar() const {
        assert(_grammar);
        return *_grammar;
    }

    bool operator==(const Unit& other) const { return typeID() == other.typeID(); }

    // Type interface.
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }

    // type::trait::Parameterized interface.
    auto typeParameters() const { return childs(); }
    auto isWildcard() const { return _wildcard; }

    // Node interface.
    auto properties() const { return node::Properties{{"public", _public}}; }

    /**
     * Copies an existing unit type but changes it ``public`` state.
     *
     * @param unit original unit type
     * @param p true if the copied type is to be public
     * @return new type with ``public`` state set as requested
     */
    static Unit setPublic(const Unit& unit, bool p) {
        auto x = Type(unit)._clone().as<Unit>();
        x._public = p;
        return x;
    }

    /**
     * Copies an existing unit type, adding further unit items.
     *
     * @param unit original unit type
     * @param items additional items to add
     * @return new unit type that includes the additional items
     */
    static Unit addItems(const Unit& unit, const std::vector<unit::Item>& items) {
        auto x = Type(unit)._clone().as<Unit>();
        for ( auto i : items )
            x.childs().emplace_back(std::move(i));

        return x;
    }

    /**
     * Copies an existing unit type, setting its accociated grammar.
     *
     * @param unit original unit type
     * @param g the grammar
     * @return new type with the grammar associated
     */
    static Unit setGrammar(const Unit& unit, std::shared_ptr<spicy::detail::codegen::Grammar> g) {
        auto x = Type(unit)._clone().as<Unit>();
        x._grammar = std::move(g);
        return x;
    }

private:
    bool _public = false;
    bool _wildcard = false;
    std::shared_ptr<detail::codegen::Grammar> _grammar;
};


} // namespace type
} // namespace spicy
