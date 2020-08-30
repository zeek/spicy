// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
// Wrapper for including doctest.h.

#pragma once

#ifdef __APPLE__
#ifndef __MAC_OS_X_VERSION_MIN_REQUIRED
// doctests uses this for platform detection, but it's not always defined.
// Just set it to some dummy value.
#define __MAC_OS_X_VERSION_MIN_REQUIRED 1000
#endif
#endif

#include <doctest/doctest.h>
