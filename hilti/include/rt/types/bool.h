// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/extension-points.h>

namespace hilti::rt {

namespace detail::adl {
inline std::string to_string(bool x, adl::tag /*unused*/) { return (x ? "True" : "False"); }

} // namespace detail::adl

} // namespace hilti::rt
