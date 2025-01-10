// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#ifdef HILTI_HAVE_ASAN
// This following injects ASAN options. Note that this works on macOS, but
// *not* work on Linux because there the ASAN runtime's weak version of the
// same symbol seems to be winning during linking. However, the only option we
// set here is "detect_leaks", which on Linux is already on by default (but not
// on macOS).
extern "C" {
const char* __asan_default_options() { return "detect_leaks=1"; }
}
#endif
