// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <cstring>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/backtrace.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

Backtrace::Backtrace() {
#ifdef HILTI_HAVE_BACKTRACE
    _frames = ::backtrace(_callstack, sizeof(_callstack));
#endif
}

std::vector<std::string> Backtrace::backtrace() const {
    std::vector<std::string> bt;

#ifdef HILTI_HAVE_BACKTRACE
    assert(_frames >= 0);
    char** strings = backtrace_symbols(_callstack, _frames);
    if ( ! strings ) {
        bt.push_back("# <trouble resolving backtrace symbols>");
        return bt;
    }

    for ( auto i = 0; i < _frames; i++ ) {
        auto p1 = strchr(strings[i], '(');
        auto p2 = p1 ? strchr(p1, '+') : nullptr;
        auto p3 = p2 ? strchr(p2, ')') : nullptr;
        if ( p1 && p2 && p3 ) {
            *p2 = '\0';
            bt.push_back(fmt("# %s %s", p3 + 2, demangle(p1 + 1)));
        }
        else
            bt.push_back(fmt("# %s", strings[i]));
    }

    free(strings); // NOLINT
#else
    bt.push_back("# <support for stack backtraces not available>");
#endif

    return bt;
}

bool hilti::rt::operator==(const Backtrace& a, const Backtrace& b) {
    if ( a._frames < 0 && b._frames < 0 )
        return true;

    if ( a._frames != b._frames )
        return false;

    for ( int i = 0; i < a._frames; i++ ) {
        if ( a._callstack[i] != b._callstack[i] )
            return false;
    }

    return true;
}
