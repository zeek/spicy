// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/look-ahead.h>

using namespace spicy;
using namespace spicy::detail;

bool codegen::production::LookAhead::supportsSynchronize() const {
    if ( hasSize() )
        return true;

    for ( const auto& t : _lahs->first ) {
        if ( ! t.supportsSynchronize() )
            return false;
    }

    for ( const auto& t : _lahs->second ) {
        if ( ! t.supportsSynchronize() )
            return false;
    }

    return true;
}

static std::string _fmtAlt(const codegen::Production& alt, const std::set<codegen::Production>& lahs) {
    auto fmt = [&](const auto& lah) {
        if ( lah.isLiteral() )
            return hilti::util::fmt("%s (id %" PRId64 ")", lah.render(), lah.tokenID());

        return hilti::util::fmt("%s (not a literal)", lah.render());
    };

    return hilti::util::fmt("{%s}: %s", hilti::util::join(hilti::util::transform(lahs, fmt), ", "), alt.symbol());
}

std::string codegen::production::LookAhead::render() const {
    return _fmtAlt(_alternatives.first, _lahs->first) + " | " + _fmtAlt(_alternatives.second, _lahs->second);
}
