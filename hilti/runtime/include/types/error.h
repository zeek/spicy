// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/result.h>
#include <hilti/rt/util.h>

namespace hilti::rt::detail::adl {
inline std::string to_string(const result::Error& x, adl::tag /*unused*/) {
    if ( ! x.description().empty() )
        return fmt("<error: %s>", x.description());

    return "<error>";
}

} // namespace hilti::rt::detail::adl
