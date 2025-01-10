// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/3rdparty/tinyformat/tinyformat.h>

namespace hilti::rt {

/** sprintf-style string formatting. */
template<typename... Args>
std::string fmt(const char* fmt, const Args&... args) {
    return tfm::format(fmt, args...);
}

/** sprintf-style string formatting. */
template<typename... Args>
std::string fmt(std::string_view s, const Args&... args) {
    // In principal we do not know whether the passed `string_view` is
    // null-terminated, so `s.data()` could end up accessing out of bounds
    // data. In generated code `s` is always null-terminated though.
    //
    // NOTE: If we ever wanted to make this safe for views not null-terminated,
    // a fix would be to expand `s` into a true, null-terminated `const char*`,
    // e.g.,
    //
    //     char buf[1024];
    //     snprintf(buf, sizeof(buf), "%.*s", static_cast<int>(s.length()), s.data());
    //     return fmt(buf, args...);
    return fmt(s.data(), args...); // NOLINT(bugprone-suspicious-stringview-data-usage)
}
} // namespace hilti::rt
