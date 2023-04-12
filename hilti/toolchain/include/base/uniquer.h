// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/base/cache.h>
#include <hilti/base/util.h>

namespace hilti::util {

/**
 * Specialized cache that makes IDs unique, based on previously created ones.
 * The *ID* type must allow assignment from string to set its value.
 */
template<typename ID>
class Uniquer : private Cache<ID, bool> {
public:
    /**
     * If we see *id* for the 1st time, returns it (potentially normalized).
     * Otherwise returns a modified version that's guaranteed to not have
     * been returned before.
     *
     * @param normalize If true, always modifies the returned ID to be a
     * valid C ID.
     */
    ID get(ID name, bool normalize = true) {
        if ( normalize )
            name = util::toIdentifier(name);

        auto x = name;
        int i = 1;
        while ( true ) {
            if ( ! this->has(x) ) {
                this->put(x, true);
                return x;
            }

            x = util::fmt("%s_%d", name, ++i);
        }
    }

    /** Clears a previously returned name for reuse. */
    void remove(const ID& id) { this->Cache<ID, bool>::remove(id); }
};

} // namespace hilti::util
