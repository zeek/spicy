// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>

namespace hilti::rt::detail::adl {

template<typename R, typename... Args>
inline std::string to_string(std::function<R(Args...)>, adl::tag /*unused*/) {
    return "<function>";
}

template<typename R, typename... Args>
inline std::string to_string(R (*)(Args...), adl::tag /*unused*/) {
    return "<function>";
}

} // namespace hilti::rt::detail::adl
