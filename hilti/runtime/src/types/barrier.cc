// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/types/barrier.h>

using namespace hilti::rt;

void Barrier::wait() {
    while ( true ) {
        if ( isReleased() )
            return;

        if ( isAborted() )
            throw BarrierAborted("broken barrier");

        detail::yield(true);
    }
}

void Barrier::arrive() {
    if ( isReleased() || isAborted() )
        return;

    ++_arrived;
}

void Barrier::abort() {
    if ( ! isReleased() )
        _expected = -1;
}

Barrier::operator std::string() const {
    if ( isAborted() )
        return "<barrier aborted>";
    else
        return fmt("<barrier %" PRIu64 "/%" PRIu64 ">", _arrived, _expected);
}
