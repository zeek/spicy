// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/any.h>
#include <hilti/rt/extension-points.h>

namespace hilti::rt {

namespace detail::adl {
inline std::string to_string(const hilti::rt::any& x, adl::tag /*unused*/) { return "<any value>"; }

} // namespace detail::adl

} // namespace hilti::rt
