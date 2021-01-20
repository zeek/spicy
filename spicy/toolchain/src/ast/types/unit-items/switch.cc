// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-items/switch.h>

using namespace spicy;
using namespace spicy::detail;

bool spicy::type::unit::item::Switch::hasNoFields() const {
    for ( const auto& c : cases() ) {
        for ( const auto& f : c.items() ) {
            if ( ! f.itemType().isA<type::Void>() )
                return false;
        }
    }

    return true;
}

std::optional<spicy::type::unit::item::switch_::Case> spicy::type::unit::item::Switch::case_(
    const type::unit::item::Field& x) {
    for ( const auto& c : cases() ) {
        for ( const auto& f : c.items() ) {
            if ( f == x )
                return c;
        }
    }

    return {};
}
