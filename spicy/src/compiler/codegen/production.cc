// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

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
    auto name = util::rsplit1(p.typename_(), "::").second;

    std::string can_sync;
    std::string sync_at;
    std::string kind;
    std::string field;
    std::string container;

    bool have_sync = p.meta().field() && AttributeSet::find(p.meta().field()->attributes(), "&synchronize");

    if ( p.maySynchronize() || p.supportsSynchronize() || have_sync )
        can_sync = util::fmt(" (sync %c/%c/%c)", p.maySynchronize() ? '+' : '-', p.supportsSynchronize() ? '+' : '-',
                             have_sync ? '+' : '-');

    std::string id = "n/a";

    if ( p.isLiteral() )
        id = util::fmt("%" PRId64, p.tokenID());

    if ( auto f = p.meta().field() ) {
        std::string args;

        if ( auto x = f->arguments(); x.size() ) {
            args = util::fmt(", args: (%s)",
                             util::join(util::transform(x, [](auto& a) { return util::fmt("%s", a); }), ", "));

            field = util::fmt(" (field '%s', id %s, %s%s)", f->id(), id, to_string(f->engine()), args);
        }
    }

    if ( auto f = p.meta().container() )
        container = util::fmt(" (container '%s')", f->id());

    return util::fmt("%10s: %-3s -> %s%s%s%s", name, p.symbol(), p.render(), field, container, can_sync);
}

int64_t codegen::production::tokenID(const std::string& p) {
    // We record the IDs in a global map to keep them stable.
    static std::unordered_map<std::string, int64_t> ids;

    if ( auto i = ids.find(p); i != ids.end() )
        return i->second;

    return ids[p] = ids.size() + 1;
}
