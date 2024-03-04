// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/name.h>

using namespace hilti;

bool type::Name::isResolved(node::CycleDetector* cd) const {
    if ( ! _resolved_type_index )
        return false;

    if ( cd && cd->haveSeen(this) )
        return true;

    auto t = resolvedType();
    assert(t);

    if ( ! cd ) {
        node::CycleDetector cd;
        cd.recordSeen(this);
        return t->isResolved(&cd);
    }

    if ( cd )
        cd->recordSeen(this);

    return t->isResolved(cd);
}
