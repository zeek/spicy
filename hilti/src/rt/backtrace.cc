// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <cstring>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/backtrace.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

Backtrace::Backtrace() {
#ifdef HILTI_HAVE_BACKTRACE
    void* callstack[128];
    int frames = ::backtrace(callstack, 128);

    char** strings;

    strings = backtrace_symbols(callstack, frames);
    assert(strings);

    for ( auto i = 0; i < frames; i++ ) {
        auto p1 = strchr(strings[i], '(');
        auto p2 = p1 ? strchr(p1, '+') : nullptr;
        auto p3 = p2 ? strchr(p2, ')') : nullptr;
        if ( p1 && p2 && p3 ) {
            *p2 = '\0';
            _backtrace.push_back(fmt("# %s %s", p3 + 2, demangle(p1 + 1)));
        }
        else
            _backtrace.push_back(fmt("# %s", strings[i]));
    }

    free(strings); // NOLINT
#else
    _backtrace.push_back("# <support for stack backtraces not available>");
#endif
}
