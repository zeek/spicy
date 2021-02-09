// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/3rdparty/any/any.hpp>

namespace hilti::rt {

// We ran into some trouble with older versions of hilti::rt::any::any on some
// platforms, so we're bringing in an external implementation for the time
// being. Specifically, we observed the issue in
// https://stackoverflow.com/a/52414724 on Debian 10, with no obvious way to
// work around it. See https://github.com/zeek/spicy/issues/629 for the full
// discussion.
//
// Note that this implementation pulls in the *experimental* any interface,
// which is slightly different from the standardized C++17 API.
namespace any = linb;

} // namespace hilti::rt
