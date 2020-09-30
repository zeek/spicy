// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

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
inline std::pair<std::vector<unit::Item>, uint64_t> assignIndices(std::vector<unit::Item> items, uint64_t index);

/**
 * Helper function to recursively number all fields in the passed switch in sequential order.
 *
 * @param switch_ the switch statement to number
 * @param index start index to use
 * @return a pair of mutated items and the next index
 */
inline auto assignIndices(unit::item::Switch switch_, uint64_t index) {
    std::vector<unit::item::switch_::Case> cases;
    cases.reserve(switch_.cases().size());

    for ( auto&& case_ : switch_.cases() ) {
        auto [new_items, new_index] = assignIndices(case_.items(), index);
        index = new_index;

        if ( case_.isDefault() )
            cases.emplace_back(case_.items(), case_.meta());
        else if ( case_.isLookAhead() ) {
            assert(case_.items().size() == 1u);
            cases.emplace_back(case_.items().at(0), case_.meta());
        }
        else
            cases.emplace_back(case_.expressions(), std::move(new_items), case_.meta());
    }

    return std::make_pair(unit::item::Switch(switch_.expression(), std::move(cases), switch_.engine(),
                                             switch_.condition(), switch_.hooks(), switch_.meta()),
                          index);
}

/**
 * Helper function to recursively number all fields in the passed list in sequential order
 *
 * @param items the items to number
 * @param index start index to use
 * @return a pair of mutated items and the next index
 */
inline std::pair<std::vector<unit::Item>, uint64_t> assignIndices(std::vector<unit::Item> items, uint64_t index) {
    std::vector<unit::Item> new_items;
    new_items.reserve(items.size());

    for ( auto item : items ) {
        if ( auto&& field = item.tryAs<unit::item::UnresolvedField>() )
            new_items.push_back(unit::item::UnresolvedField::setIndex(std::move(*field), index++));
        else if ( auto&& field = item.tryAs<unit::item::Field>() )
            new_items.push_back(unit::item::Field::setIndex(std::move(*field), index++));
        else if ( auto&& switch_ = item.tryAs<unit::item::Switch>() ) {
            auto [new_switch, new_index] = assignIndices(std::move(*switch_), index);
            index = new_index;
            new_items.push_back(std::move(new_switch));
        }
        else
            new_items.push_back(std::move(item));
    }

    return std::make_pair(new_items, index);
}
} // namespace detail

/** AST node for a Spicy unit. */
class Unit : public hilti::TypeBase,
             hilti::type::trait::isAllocable,
             hilti::type::trait::isParameterized,
             hilti::type::trait::isOnHeap {
public:
    Unit(std::vector<type::function::Parameter> p, std::vector<unit::Item> i,
         const std::optional<AttributeSet>& /* attrs */ = {}, Meta m = Meta())
        : TypeBase(nodes(std::move(p), detail::assignIndices(std::move(i), 0).first), std::move(m)) {
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
    const spicy::detail::codegen::Grammar& grammar() const {
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
    static Unit addItems(const Unit& unit, std::vector<unit::Item> items) {
        auto childs = unit.childs();
        childs.reserve(childs.size() + items.size());

        uint64_t index = 0;
        for ( auto item : items ) {
            auto [new_items, new_index] = detail::assignIndices({item}, index);
            childs.insert(childs.end(), std::move_iterator(new_items.begin()), std::move_iterator(new_items.end()));
            index = new_index;
        }
        childs.insert(childs.end(), items.begin(), items.end());

        auto x = Type(unit)._clone().as<Unit>();
        x.childs() = std::move(childs);

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
    std::shared_ptr<spicy::detail::codegen::Grammar> _grammar;
};


} // namespace type
} // namespace spicy
