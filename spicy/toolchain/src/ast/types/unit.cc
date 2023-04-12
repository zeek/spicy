// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

static NodeRef _itemByName(const Node& i, const ID& id) {
    if ( auto x = i.tryAs<type::unit::item::Field>(); x && x->id() == id )
        return NodeRef(i);

    if ( auto x = i.tryAs<type::unit::item::Variable>(); x && x->id() == id )
        return NodeRef(i);

    if ( auto x = i.tryAs<type::unit::item::Sink>(); x && x->id() == id )
        return NodeRef(i);

    if ( auto x = i.tryAs<type::unit::item::Switch>() ) {
        for ( const auto& c : x->cases() ) {
            for ( const auto& si : c.itemRefs() ) {
                if ( auto x = _itemByName(*si, id) )
                    return x;
            }
        }
    }

    return {};
}

hilti::optional_ref<const type::unit::Item> type::Unit::itemByName(const ID& id) const {
    for ( const auto& i : itemRefs() ) {
        if ( auto x = _itemByName(i, id) )
            return x->as<type::unit::Item>();
    }

    return {};
}

NodeRef type::Unit::itemRefByName(const ID& id) const {
    for ( const auto& i : itemRefs() ) {
        if ( auto x = _itemByName(*i, id) )
            return x;
    }

    return {};
}

struct AssignFieldIndicesVisitor : public hilti::visitor::PreOrder<void, AssignFieldIndicesVisitor> {
    AssignFieldIndicesVisitor(uint64_t next_index) : next_index(next_index) {}

    result_t operator()(const type::unit::item::Field& n, position_t p) {
        p.node.as<type::unit::item::Field>().setIndex(next_index++);
    }

    result_t operator()(const type::unit::item::UnresolvedField& n, position_t p) {
        p.node.as<type::unit::item::UnresolvedField>().setIndex(next_index++);
    }

    uint64_t next_index;
};

std::vector<type::unit::Item> type::detail::AssignIndices::assignIndices(std::vector<unit::Item> items) {
    std::vector<unit::Item> new_items;
    new_items.reserve(items.size());

    AssignFieldIndicesVisitor v(_next_index);

    for ( auto&& item : items ) {
        auto nitem = Node(std::move(item));
        for ( auto&& c : v.walk(&nitem) )
            v.dispatch(c);

        new_items.push_back(std::move(nitem.as<type::unit::Item>()));
    }

    _next_index = v.next_index;
    return new_items;
}
