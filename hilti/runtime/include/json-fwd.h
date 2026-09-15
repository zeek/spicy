// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

// `3rdparty/json/include` is on the build-time include path, and post-install
// `nlohmann/` is installed under the include prefix, so this bare path
// resolves in both cases without relying on the `hilti/rt/3rdparty/nlohmann`
// directory symlink which does not work on Windows.
#include <nlohmann/json_fwd.hpp>
