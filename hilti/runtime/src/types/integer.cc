// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <arpa/inet.h>

#include <algorithm>
#include <tuple>

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
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<uint64_t> x, adl::tag /*unused*/) {
    return fmt("%" PRIu64, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<int64_t> x, adl::tag /*unused*/) {
    return fmt("%" PRId64, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<uint32_t> x, adl::tag /*unused*/) {
    return fmt("%" PRIu32, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<int32_t> x, adl::tag /*unused*/) {
    return fmt("%" PRId32, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<uint16_t> x, adl::tag /*unused*/) {
    return fmt("%" PRIu16, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<int16_t> x, adl::tag /*unused*/) {
    return fmt("%" PRId16, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<uint8_t> x, adl::tag /*unused*/) {
    return fmt("%" PRIu8, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<int8_t> x, adl::tag /*unused*/) {
    return fmt("%" PRId8, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(hilti::rt::integer::safe<char> x, adl::tag /*unused*/) {
    return fmt("%" PRId8, *x.Ptr());
}
std::string hilti::rt::detail::adl::to_string(uint64_t x, adl::tag /*unused*/) { return fmt("%" PRIu64, x); }
std::string hilti::rt::detail::adl::to_string(int64_t x, adl::tag /*unused*/) { return fmt("%" PRId64, x); }
std::string hilti::rt::detail::adl::to_string(uint32_t x, adl::tag /*unused*/) { return fmt("%" PRIu32, x); }
std::string hilti::rt::detail::adl::to_string(int32_t x, adl::tag /*unused*/) { return fmt("%" PRId32, x); }
std::string hilti::rt::detail::adl::to_string(uint16_t x, adl::tag /*unused*/) { return fmt("%" PRIu16, x); }
std::string hilti::rt::detail::adl::to_string(int16_t x, adl::tag /*unused*/) { return fmt("%" PRId16, x); }
std::string hilti::rt::detail::adl::to_string(uint8_t x, adl::tag /*unused*/) { return fmt("%" PRIu8, x); }
std::string hilti::rt::detail::adl::to_string(int8_t x, adl::tag /*unused*/) { return fmt("%" PRId8, x); }
int64_t hilti::rt::integer::flip(int64_t v, uint64_t n) {
    if ( n == 0 )
        return v;
    auto i = static_cast<uint64_t>(v);
    i = flip64(i) >> (64 - n * 8);
    return static_cast<int64_t>(i);
}
uint64_t hilti::rt::integer::flip(uint64_t v, uint64_t n) {
    if ( n == 0 )
        return v;
    return (flip64(v) >> (64 - n * 8));
}
