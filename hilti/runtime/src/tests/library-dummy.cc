// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/linker.h>
#include <hilti/rt/util.h>

#ifndef RETURN_VALUE
#error RETURN_VALUE is undefined. Set it to an integer value to return from the function in this library.
#endif

extern "C" {
HILTI_EXPORT int foo() { return RETURN_VALUE; }

// Wrap in extern "C" to prevent name mangling so that
// GetProcAddress can find this symbol by its undecorated name on Windows.
const char HILTI_EXPORT HILTI_WEAK* HILTI_INTERNAL_GLOBAL(hlto_library_version) = R"({
    "magic": "v1",
    "hilti_version": 400,
    "created": 0,
    "debug": false,
    "optimize": false
})";
}
