// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/computed.h>
#include <hilti/ast/types/tuple.h>

#include <spicy/ast/types/bitfield.h>

using namespace spicy;

Type type::bitfield::Bits::type() const {
    if ( auto a = AttributeSet::find(attributes(), "&convert") )
        return hilti::type::Computed(*a->valueAs<Expression>(), meta());

    return hilti::type::UnsignedInteger(_field_width);
}

Type type::Bitfield::type() const {
    std::vector<std::pair<ID, Type>> elems;

    for ( const auto& b : bits() )
        elems.emplace_back(b.id(), b.type());

    return type::Tuple(std::move(elems), meta());
}

std::optional<int> type::Bitfield::bitsIndex(const ID& id) const {
    for ( const auto&& [i, b] : hilti::util::enumerate(bits()) ) {
        if ( id == b.id() )
            return i;
    }

    return {};
}

std::optional<type::bitfield::Bits> type::Bitfield::bits(const ID& id) const {
    for ( const auto& b : bits() ) {
        if ( id == b.id() )
            return b;
    }

    return {};
}
