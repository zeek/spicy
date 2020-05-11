// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>

namespace hilti::rt {
class Bytes;
}

namespace spicy::rt {

/** Returns a string identifying the version of the runtime library. */
extern std::string version();

/** Returns a bytes value rendered as a hex string. */
extern std::string bytes_to_hexstring(const hilti::rt::Bytes& value);

/** Returns the value of an environment variable, if set. */
extern std::optional<std::string> getenv(const std::string& name);

} // namespace spicy::rt
