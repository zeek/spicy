// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/result.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace detail::adl {
inline std::string to_string(const result::Error& x, adl::tag /*unused*/) {
    if ( ! x.description().empty() )
        return fmt("<error: %s>", x.description());

    return "<error>";
}

} // namespace detail::adl

} // namespace hilti::rt
