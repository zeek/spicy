// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/grammar.h>

using namespace spicy;

std::optional<type::unit::Item> type::Unit::field(const ID& id) const {
    for ( const auto& f : hilti::node::flattenedChilds<type::unit::item::Field>(*this) ) {
        if ( f.id() == id )
            return f;
    }

    return {};
}
