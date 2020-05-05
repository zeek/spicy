// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>

namespace spicy::rt {

/** Returns a string identifying the version of the runtime library. */
extern std::string version();

/** Returns the value of an environment variable, if set. */
extern std::optional<std::string> getenv(const std::string& name);

} // namespace spicy::rt
