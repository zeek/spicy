// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "spicy/ast/types/unit.h"

#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

std::optional<type::unit::Item> type::Unit::field(const ID& id) const {
    for ( const auto& f : hilti::node::flattenedChilds<type::unit::item::Field>(*this) ) {
        if ( f.id() == id )
            return f;
    }

    return {};
}

struct AssignFieldIndicesVisitor : public hilti::visitor::PreOrder<void, AssignFieldIndicesVisitor> {
    AssignFieldIndicesVisitor(uint64_t next_index) : next_index(next_index) {}

    result_t operator()(const type::unit::item::Field& n, position_t p) {
        p.node = type::unit::Item(type::unit::item::Field::setIndex(n, next_index++));
    }

    result_t operator()(const type::unit::item::UnresolvedField& n, position_t p) {
        p.node = type::unit::Item(type::unit::item::UnresolvedField::setIndex(n, next_index++));
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
