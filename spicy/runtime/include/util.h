// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <tuple>

#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/vector.h>

#include <spicy/rt/parser.h>

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

/** Confirm a unit in trial mode. */
template<typename U>
inline void confirm(U& p) {
    // If we are not in trial mode `confirm` is a no-op.
    if ( p.__trial_mode ) {
        p.__trial_mode.reset();
        p.__on_0x25_confirmed();
    }
}

/** Reject a unit in trial or any other mode. */
template<typename U>
inline void reject(U& p) {
    // Only invoke hook if we were actually in trial mode.
    if ( const auto& trial_mode = p.__trial_mode ) {
        p.__on_0x25_rejected();
        throw *trial_mode;
    }
    else
        throw spicy::rt::ParseError("unit rejected outside of trial mode");
}

} // namespace spicy::rt
