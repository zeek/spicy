// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// Wrapper for including doctest.h.

#pragma once

#ifdef __APPLE__
#ifndef __MAC_OS_X_VERSION_MIN_REQUIRED
// doctest uses this macro for platform detection, but it's not always defined
// for me. If doctest doesn't recognize the platform, break-into-debugger
// won't be supported. We just set it to some dummy value, that'll doctest
// believe we are on macOS.
#define __MAC_OS_X_VERSION_MIN_REQUIRED 1000
#endif
#endif

#include <doctest/doctest.h>
