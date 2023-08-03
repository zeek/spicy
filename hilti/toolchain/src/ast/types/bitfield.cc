// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/tuple.h>

using namespace hilti;

hilti::optional_ref<const type::bitfield::Bits> type::Bitfield::bits(const ID& id) const {
    for ( const auto& b : bits() ) {
        if ( id == b.id() )
            return b;
    }

    return {};
}

std::optional<int> type::Bitfield::bitsIndex(const ID& id) const {
    for ( const auto&& [i, b] : hilti::util::enumerate(bits()) ) {
        if ( id == b.id() )
            return i;
    }

    return {};
}
