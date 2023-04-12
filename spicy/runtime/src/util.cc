// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/autogen/version.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/util.h>

#include <spicy/rt/autogen/config.h>
#include <spicy/rt/util.h>

std::string spicy::rt::version() {
    constexpr char spicy_version[] = PROJECT_VERSION_STRING_LONG;

#if HILTI_RT_BUILD_TYPE_DEBUG
    return hilti::rt::fmt("Spicy runtime library version %s [debug build]", spicy_version);
#elif HILTI_RT_BUILD_TYPE_RELEASE
    return hilti::rt::fmt("Spicy runtime library version %s [release build]", spicy_version);
#else
#error "Neither HILTI_RT_BUILD_TYPE_DEBUG nor HILTI_RT_BUILD_TYPE_RELEASE define."
#endif
}

std::string spicy::rt::bytes_to_hexstring(const hilti::rt::Bytes& value) {
    std::string result;

    for ( auto x : value )
        result += hilti::rt::fmt("%02X", x);

    return result;
}

const hilti::rt::Vector<
    std::optional<std::tuple<hilti::rt::integer::safe<uint64_t>, std::optional<hilti::rt::integer::safe<uint64_t>>>>>*
spicy::rt::get_offsets_for_unit(const hilti::rt::type_info::Struct& struct_, const hilti::rt::type_info::Value& value) {
    for ( const auto& [f, v] : struct_.iterate(value, /*include_internal=*/true) ) {
        if ( f.name == "__offsets" )
            return static_cast<decltype(get_offsets_for_unit(struct_, value))>(v.pointer());
    }

    return nullptr;
}
