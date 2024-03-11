// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/reference.h>

using namespace spicy;
using namespace spicy::detail;

const codegen::Production* codegen::Production::follow() const {
    auto p = this;
    while ( auto r = dynamic_cast<const production::Reference*>(p) )
        p = r->production();

    return p;
}

codegen::Production* codegen::Production::follow() {
    auto p = this;
    while ( auto r = dynamic_cast<production::Reference*>(p) )
        p = r->production();

    return p;
}

std::string codegen::Production::print() const { return hilti::util::trim(to_string(*this)); }

bool codegen::production::isNullable(const std::vector<std::vector<Production*>>& rhss) {
    if ( rhss.empty() )
        return true;

    for ( const auto& rhs : rhss ) {
        for ( auto& r : rhs ) {
            if ( ! r->isNullable() )
                goto next;
        }
        return true;
    next:
        continue;
    }

    return false;
}

std::string codegen::to_string(const Production& p) {
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
                                                                             [](auto a) {
                                                                                 return hilti::util::fmt("%s", a);
                                                                             }),
                                                      ", "));

            field = hilti::util::fmt(" (field '%s', id %s, %s%s)", f->id(), id, to_string(f->engine()), args);
        }
    }

    if ( auto f = p.meta().container() )
        container = hilti::util::fmt(" (container '%s')", f->id());

    auto prefix = "";
    auto postfix = "";
    auto name = p.typename_();
    auto render = p.dump();

    if ( const auto* ref =
             dynamic_cast<const production::Reference*>(&p) ) { // don't use `tryAs`, it follows the reference
        prefix = "Ref(";
        postfix = ")";
        name = ref->production()->typename_();
        render = ref->production()->dump();
    }

    name = prefix + hilti::util::rsplit1(name, "::").second + postfix;

    return hilti::util::fmt("%15s: %-3s -> %s%s%s%s", name, p.symbol(), render, field, container, can_sync);
}

uint64_t codegen::Production::tokenID(const std::string& p) {
    // We record the IDs in a global map to keep them stable.
    static std::unordered_map<std::string, size_t> ids;

    if ( auto i = ids.find(p); i != ids.end() )
        return i->second;

    return ids[p] = ids.size() + 1;
}
