// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/any.h>
#include <hilti/rt/extension-points.h>

namespace hilti::rt::detail::adl {
inline std::string to_string(const hilti::rt::any& x, adl::tag /*unused*/) { return "<any value>"; }

} // namespace hilti::rt::detail::adl
