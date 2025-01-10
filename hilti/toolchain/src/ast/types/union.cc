// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/union.h>

using namespace hilti;

bool type::Union::isResolved(node::CycleDetector* cd) const {
    const auto& cs = children();

    return std::all_of(cs.begin(), cs.end(), [&](const auto& c) {
        if ( auto f = c->template tryAs<declaration::Field>() )
            return f->isResolved(cd);

        else if ( auto p = c->template tryAs<type::function::Parameter>() )
            return p->isResolved(cd);

        return true;
    });
}
