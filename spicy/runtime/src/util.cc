// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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


static inline void byte_to_hex(unsigned char byte, char* hex_out) {
    static constexpr char hex_chars[] = "0123456789ABCDEF";
    hex_out[0] = hex_chars[(byte & 0xf0) >> 4];
    hex_out[1] = hex_chars[byte & 0x0f];
}

std::string spicy::rt::bytes_to_hexstring(const hilti::rt::Bytes& value) {
    const auto& data = value.str();

    if ( data.empty() )
        return "";

    std::string result;
    result.resize(data.size() * 2); // 2 digits per hex byte

    for ( unsigned long i = 0; i < data.size(); i++ )
        byte_to_hex(data[i], &result[i * 2]);

    return result;
}

std::string spicy::rt::bytes_to_mac(const hilti::rt::Bytes& value) {
    const auto& data = value.str();

    if ( data.empty() )
        return "";

    // Two digits per hex byte, plus one colon per byte except the last.
    std::string result((data.size() * 2) + (data.size() - 1), ':');

    for ( unsigned long i = 0; i < data.size(); i++ )
        byte_to_hex(data[i], &result[i * 3]);

    return result;
}

const hilti::rt::Map<std::string, hilti::rt::Tuple<hilti::rt::integer::safe<uint64_t>,
                                                   hilti::rt::Optional<hilti::rt::integer::safe<uint64_t>>>>*
spicy::rt::get_offsets_for_unit(const hilti::rt::type_info::Struct& struct_, const hilti::rt::type_info::Value& value) {
    for ( const auto& [f, v] : struct_.iterate(value, /*include_internal=*/true) ) {
        if ( f.name == "__offsets" )
            return static_cast<decltype(get_offsets_for_unit(struct_, value))>(v.pointer());
    }

    return nullptr;
}
