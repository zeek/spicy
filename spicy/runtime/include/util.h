// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <tuple>

#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/vector.h>

namespace hilti::rt {
class Bytes;

namespace type_info {
class Struct;
class Value;
}; // namespace type_info
} // namespace hilti::rt

namespace spicy::rt {

/** Returns a string identifying the version of the runtime library. */
extern std::string version();

/** Returns a bytes value rendered as a hex string. */
extern std::string bytes_to_hexstring(const hilti::rt::Bytes& value);

/** Returns the internal `__offsets` member if present. */
extern const hilti::rt::Vector<
    std::optional<std::tuple<hilti::rt::integer::safe<uint64_t>, std::optional<hilti::rt::integer::safe<uint64_t>>>>>*
get_offsets_for_unit(const hilti::rt::type_info::Struct& struct_, const hilti::rt::type_info::Value& value);

} // namespace spicy::rt
