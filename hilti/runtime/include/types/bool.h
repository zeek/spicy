// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>

namespace hilti::rt {

class Bool {
public:
    constexpr Bool() = default;
    constexpr /*implicit*/ Bool(bool value) : _value(value) {}

    constexpr /*implicit*/ operator bool() const { return _value; }

private:
    bool _value = false;
};

namespace detail::adl {
inline std::string to_string(bool x, adl::tag /*unused*/) { return (x ? "True" : "False"); }
inline std::string to_string(Bool x, adl::tag /*unused*/) { return hilti::rt::to_string(static_cast<bool>(x)); }

} // namespace detail::adl

} // namespace hilti::rt
