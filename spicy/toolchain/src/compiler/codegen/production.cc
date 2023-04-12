// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/compiler/detail/codegen/production.h>

using namespace spicy;
using namespace spicy::detail;

bool codegen::production::nullable(const std::vector<std::vector<Production>>& rhss) {
    if ( rhss.empty() )
        return true;

    for ( const auto& rhs : rhss ) {
        for ( auto& r : rhs ) {
            if ( ! r.nullable() )
                goto next;
        }
        return true;
    next:
        continue;
    }

    return false;
}

std::string codegen::production::to_string(const Production& p) {
    auto name = hilti::util::rsplit1(p.typename_(), "::").second;

    std::string can_sync;
    std::string sync_at;
    std::string kind;
    std::string field;
    std::string container;

    std::string id = "n/a";

    if ( p.isLiteral() )
        id = hilti::util::fmt("%" PRId64, p.tokenID());

    if ( auto f = p.meta().field() ) {
        std::string args;

        if ( auto x = f->arguments(); x.size() ) {
            args = hilti::util::fmt(", args: (%s)",
                                    hilti::util::join(hilti::node::transform(x,
                                                                             [](auto& a) {
                                                                                 return hilti::util::fmt("%s", a);
                                                                             }),
                                                      ", "));

            field = hilti::util::fmt(" (field '%s', id %s, %s%s)", f->id(), id, to_string(f->engine()), args);
        }
    }

    if ( auto f = p.meta().container() )
        container = hilti::util::fmt(" (container '%s')", f->id());

    return hilti::util::fmt("%10s: %-3s -> %s%s%s%s", name, p.symbol(), p.render(), field, container, can_sync);
}

uint64_t codegen::production::tokenID(const std::string& p) {
    // We record the IDs in a global map to keep them stable.
    static std::unordered_map<std::string, size_t> ids;

    if ( auto i = ids.find(p); i != ids.end() )
        return i->second;

    return ids[p] = ids.size() + 1;
}
