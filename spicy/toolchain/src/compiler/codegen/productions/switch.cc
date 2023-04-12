// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/switch.h>

using namespace spicy;
using namespace spicy::detail;

std::vector<std::vector<codegen::Production>> codegen::production::Switch::rhss() const {
    std::vector<std::vector<Production>> rhss;

    for ( const auto& c : _cases )
        rhss.push_back({c.second});

    if ( _default )
        rhss.push_back({*_default});

    return rhss;
}

std::string codegen::production::Switch::render() const {
    std::string r;

    for ( const auto& c : _cases ) {
        std::vector<std::string> exprs;

        exprs.reserve(c.first.size());
        for ( const auto& e : c.first )
            exprs.push_back(hilti::util::fmt("%s", e));

        if ( r.size() )
            r += " | ";

        r += hilti::util::fmt("[%s] -> %s", hilti::util::join(exprs, ","), c.second.symbol());
    }

    if ( _default ) {
        if ( r.size() )
            r += " | ";

        r += hilti::util::fmt(" | * -> %s", _default->symbol());
    }

    return r;
}
