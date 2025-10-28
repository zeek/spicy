// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <arpa/inet.h>

#include <algorithm>

#include <hilti/rt/types/integer.h>

using namespace hilti::rt;

namespace {
template<typename T>
T flip_impl(const T& v) {
    constexpr size_t N = sizeof(T);

    union { // NOLINT(hicpp-member-init)
        T t;
        unsigned char c[N];
    } x;

    x.t = v;

    for ( size_t i = 0; i < N / 2; ++i ) {
        std::swap(x.c[i], x.c[N - 1 - i]);
    }

    return x.t;
}
} // namespace

uint16_t integer::flip16(uint16_t v) { return flip_impl(v); }
uint32_t integer::flip32(uint32_t v) { return flip_impl(v); }
uint64_t integer::flip64(uint64_t v) { return flip_impl(v); }

uint64_t integer::hton64(uint64_t v) {
#if ! __BIG_ENDIAN__
    return integer::flip64(v);
#else
    return v;
#endif
}

uint32_t integer::hton32(uint32_t v) { return htonl(v); } //NOLINT(hicpp-signed-bitwise)

uint16_t integer::hton16(uint16_t v) { return htons(v); } //NOLINT(hicpp-signed-bitwise)

uint64_t integer::ntoh64(uint64_t v) {
#if ! __BIG_ENDIAN__
    return integer::flip64(v);
#else
    return v;
#endif
}

uint32_t integer::ntoh32(uint32_t v) { return ntohl(v); } //NOLINT(hicpp-signed-bitwise)

uint16_t integer::ntoh16(uint16_t v) { return ntohs(v); } //NOLINT(hicpp-signed-bitwise)

std::string detail::adl::to_string(const integer::BitOrder& x, tag /*unused*/) {
    switch ( x.value() ) {
        case integer::BitOrder::LSB0: return "BitOrder::LSB0";
        case integer::BitOrder::MSB0: return "BitOrder::MSB0";
        case integer::BitOrder::Undef: return "BitOrder::Undef";
    };

    cannot_be_reached();
}
