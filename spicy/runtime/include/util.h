// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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

/** Returns a bytes value rendered as a MAC address string. */
extern std::string bytes_to_mac(const hilti::rt::Bytes& value);

/** Returns the internal `__offsets` member if present. */
extern const hilti::rt::Map<std::string, hilti::rt::Tuple<hilti::rt::integer::safe<uint64_t>,
                                                          hilti::rt::Optional<hilti::rt::integer::safe<uint64_t>>>>*
get_offsets_for_unit(const hilti::rt::type_info::Struct& struct_, const hilti::rt::type_info::Value& value);

/** Confirm a unit in trial mode. */
template<typename U>
inline void confirm(U& p, const hilti::rt::TypeInfo* /* ti */) {
    // If we are not in trial mode `confirm` is a no-op.
    if ( p.__error ) {
        p.__error.reset();

        // TODO(bbannier): For consistence we would ideally bracket the hook
        // invocation with calls to `ParserBuilder::beforeHook` and
        // `afterHook`, but this is not possible since we have no direct access
        // to the parser state here.
        p.__on_0x25_confirmed();
    }
}

/** Reject a unit in trial or any other mode. */
template<typename U>
inline void reject(U& p, const hilti::rt::TypeInfo* /* ti */) {
    // Only invoke hook if we were actually in trial mode.
    if ( const auto& error = p.__error ) {
        // TODO(bbannier): For consistence we would ideally bracket the hook
        // invocation with calls to `ParserBuilder::beforeHook` and
        // `afterHook`, but this is not possible since we have no direct access
        // to the parser state here.
        p.__on_0x25_rejected();

        throw *error;
    }
    else
        throw spicy::rt::ParseError("unit rejected outside of trial mode");
}

} // namespace spicy::rt
