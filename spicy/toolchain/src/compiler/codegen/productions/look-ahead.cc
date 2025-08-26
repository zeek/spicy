// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/look-ahead.h>

using namespace spicy;
using namespace spicy::detail;

static std::string fmtAlt(const codegen::Production* alt, const spicy::detail::codegen::production::Set& lahs) {
    auto fmt = [&](const auto& lah) {
        auto str = hilti::util::trim(to_string(*lah));

        if ( lah->isLiteral() )
            return hilti::util::fmt("%s (id %" PRId64 ")", str, lah->tokenID());
        else
            return hilti::util::fmt("%s (not a literal)", str);
    };

    return hilti::util::fmt("{%s}: %s", hilti::util::join(hilti::util::transform(lahs, fmt), ", "), alt->symbol());
}

std::string codegen::production::LookAhead::dump() const {
    return fmtAlt(_alternatives.first.get(), _lahs.first) + " | " + fmtAlt(_alternatives.second.get(), _lahs.second);
}
