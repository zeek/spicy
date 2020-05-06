// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

namespace hilti::rt {
class Bytes;
}

namespace spicy::rt {

/** Returns a string identifying the version of the runtime library. */
extern std::string version();

/** Returns a bytes value rendered as a hex string. */
extern std::string bytes_to_hexstring(const hilti::rt::Bytes& value);

} // namespace spicy::rt
