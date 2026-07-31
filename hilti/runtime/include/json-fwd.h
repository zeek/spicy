// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-overlap-compare"
#elif defined(__GNUC__)
// Note that clang #defines __GNUC__ as well.
#pragma GCC diagnostic push
#endif

// `3rdparty/json/include` is on the build-time include path, and post-install
// `nlohmann/` is installed under the include prefix, so this bare path
// resolves in both cases without relying on the `hilti/rt/3rdparty/nlohmann`
// directory symlink which does not work on Windows.
#include <nlohmann/json_fwd.hpp>

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
