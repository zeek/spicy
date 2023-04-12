// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <cinttypes>
#include <memory>

#include <hilti/rt/context.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

namespace hilti::rt::context::detail {

// Not part of global state, it's per thread.
HILTI_THREAD_LOCAL Context* __current = nullptr;

Context*& current() { return __current; }

hilti::rt::Context* set(Context* ctx) {
    auto old = current();
    current() = ctx;
    return old;
}

} // namespace hilti::rt::context::detail

Context::Context(vthread::ID vid) : vid(vid) {
    if ( vid == vthread::Master ) {
        HILTI_RT_DEBUG("libhilti", "creating master context");
        // Globals for the master context are initialized separately as we
        // may not have the state available yet.
        return;
    }

    for ( const auto& m : globalState()->hilti_modules ) {
        if ( m.init_globals )
            (*m.init_globals)(this);
    }
}

Context::~Context() {
    if ( vid == vthread::Master ) {
        HILTI_RT_DEBUG("libhilti", "destroying master context");
    }
    else {
        HILTI_RT_DEBUG("libhilti", fmt("destroying context for vid %" PRIu64, vid));
    }
}

Context* context::detail::master() { return globalState()->master_context.get(); }
