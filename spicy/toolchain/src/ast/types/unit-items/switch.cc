// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>

#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/switch.h>
#include <spicy/ast/visitor.h>

bool spicy::type::unit::item::Switch::hasNoFields() const {
    for ( const auto& c : cases() ) {
        for ( const auto& f : c->items() ) {
            if ( ! f->itemType()->type()->isA<hilti::type::Void>() )
                return false;
        }
    }

    return true;
}

spicy::type::unit::item::switch_::Case* spicy::type::unit::item::Switch::case_(
    const type::unit::item::Field* field) const {
    for ( const auto& c : cases() ) {
        for ( const auto& i : c->items() ) {
            if ( i == field )
                return c;
        }
    }

    return {};
}
