// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/function.h>

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
