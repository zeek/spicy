// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/ast/types/function.h"

#include <algorithm>
#include <iterator>

using namespace hilti;

bool type::Function::isResolved(node::CycleDetector* cd) const {
    // We treat auto types as resolved here because (1) they don't need to /
    // should hold up resolving, and (2) could lead to resolver dead-locks if
    // we let them.

    for ( auto c = children().begin() + 1; c != children().end(); c++ ) {
        auto p = (*c)->as<declaration::Parameter>();
        if ( ! p->isResolved(cd) && ! p->type()->type()->isA<type::Auto>() )
            return false;
    }

    if ( result()->type()->isA<type::Auto>() )
        return true;

    if ( ! result()->type()->isResolved(cd) )
        return false;

    return true;
}

hilti::Result<Nothing> type::isValidOverload(Function* f1, Function* f2) {
    if ( areEquivalent(f1, f2) )
        return result::Error("functions are equivalent");

    const auto& params1 = f1->parameters();
    const auto& params2 = f2->parameters();

    auto non_defaulted = [](const node::Set<function::Parameter>& p) {
        node::Set<function::Parameter> r;
        std::copy_if(p.begin(), p.end(), std::back_inserter(r), [](function::Parameter* p) { return ! p->default_(); });
        return r;
    };

    if ( ! type::same(f1->result(), f2->result()) ) {
        if ( areEquivalent(params1, params2) )
            return result::Error("functions cannot differ only in return type");
        else if ( areEquivalent(non_defaulted(params1), non_defaulted(params2)) )
            return result::Error("functions cannot differ only in defaulted parameters");
    }

    return Nothing();
}
