// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/bitfield.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/base/util.h>

using namespace hilti;

type::bitfield::BitRange::~BitRange() = default;

type::bitfield::BitRange* type::Bitfield::bits(const ID& id) const {
    for ( const auto& b : bits(true) ) {
        if ( id == b->id() )
            return b;
    }

    return {};
}

std::optional<unsigned int> type::Bitfield::bitsIndex(const ID& id) const {
    auto i = 0U;
    ;
    for ( const auto& b : bits(true) ) {
        if ( id == b->id() )
            return i;

        i++;
    }

    return {};
}

Ctor* type::Bitfield::ctorValue(ASTContext* ctx) {
    ctor::bitfield::BitRanges values;

    for ( const auto& b : bits() ) {
        if ( auto* v = b->ctorValue() )
            values.emplace_back(ctor::bitfield::BitRange::create(ctx, b->id(), v, meta()));
    }

    if ( ! values.empty() )
        return ctor::Bitfield::create(ctx, values, QualifiedType::create(ctx, as<UnqualifiedType>(), Constness::Const),
                                      meta());
    else
        return {};
}
