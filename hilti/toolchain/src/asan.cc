// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
// We link this into a tiny static library so that it overrides the
// corresponding weak function in the ASAN runtime. (That doesn't work if
// it's just part of the standard shared HILTI library, at least not on
// Linux.)
//
// The code itself is borrowed/adapted from Chromium.

#include <cstdlib>

extern "C" __attribute__((used)) __attribute__((visibility("default"))) const char* __asan_default_options() {
    // detect_odr_violation=0: Getting erros for __asan_register_globals
    // otherwise.
    //
    // detect_leaks=1: Enable, doesn't always(?) seem to be on by default.
    return "detect_odr_violation=0:detect_leaks=1";
}

// Our CMake confiog explicitly tells the linker that this function is
// undefined, which will then lead to this whole file being included into the
// linking process.
extern "C" void _sanitizer_options_link_helper() {}
