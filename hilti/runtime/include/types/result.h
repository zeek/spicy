// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/result.h>
#include <hilti/rt/types/error.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace detail::adl {
template<typename T>
inline std::string to_string(Result<T> x, adl::tag /*unused*/) {
    return x ? hilti::rt::to_string(*x) : hilti::rt::to_string(x.error());
}

template<typename T>
inline std::string to_string_for_print(Result<T> x, adl::tag /*unused*/) {
    return x ? hilti::rt::to_string_for_print(*x) : hilti::rt::to_string(x.error());
}

} // namespace detail::adl

template<>
inline std::string detail::to_string_for_print<Result<std::string>>(const Result<std::string>& x) {
    return x ? *x : hilti::rt::to_string(x.error());
}

template<>
inline std::string detail::to_string_for_print<Result<std::string_view>>(const Result<std::string_view>& x) {
    return x ? std::string(*x) : hilti::rt::to_string(x.error());
}

} // namespace hilti::rt
