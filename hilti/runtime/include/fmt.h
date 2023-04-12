// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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
std::string fmt(const std::string& s, const Args&... args) {
    return fmt(s.c_str(), args...);
}
} // namespace hilti::rt
