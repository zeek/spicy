// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <arpa/inet.h>

#include <hilti/rt/types/integer.h>

using namespace hilti::rt;

uint16_t integer::flip16(uint16_t v) {
    union { // NOLINT(hicpp-member-init)
        uint32_t ui16;
        unsigned char c[2];
    } x;

    unsigned char c;

    x.ui16 = v;
    c = x.c[0];
    x.c[0] = x.c[1];
    x.c[1] = c;

    return x.ui16;
}

uint32_t integer::flip32(uint32_t v) {
    union { // NOLINT(hicpp-member-init)
        uint32_t ui32;
        unsigned char c[4];
    } x;

    unsigned char c;

    x.ui32 = v;
    c = x.c[0];
    x.c[0] = x.c[3];
    x.c[3] = c;
    c = x.c[1];
    x.c[1] = x.c[2];
    x.c[2] = c;

    return x.ui32;
}

uint64_t integer::flip64(uint64_t v) {
    union { //NOLINT(hicpp-member-init)
        uint64_t ui64;
        unsigned char c[8];
    } x;

    unsigned char c;

    x.ui64 = v;
    c = x.c[0];
    x.c[0] = x.c[7];
    x.c[7] = c;
    c = x.c[1];
    x.c[1] = x.c[6];
    x.c[6] = c;
    c = x.c[2];
    x.c[2] = x.c[5];
    x.c[5] = c;
    c = x.c[3];
    x.c[3] = x.c[4];
    x.c[4] = c;

    return x.ui64;
}

uint64_t integer::hton64(uint64_t v) {
#if ! __BIG_ENDIAN__
    return integer::flip64(v);
#else
    return v;
#endif
}

uint32_t integer::hton32(uint32_t v) { return ntohl(v); } //NOLINT(hicpp-signed-bitwise)

uint16_t integer::hton16(uint16_t v) { return ntohs(v); } //NOLINT(hicpp-signed-bitwise)

uint64_t integer::ntoh64(uint64_t v) {
#if ! __BIG_ENDIAN__
    return integer::flip64(v);
#else
    return v;
#endif
}

uint32_t integer::ntoh32(uint32_t v) { return ntohl(v); } //NOLINT(hicpp-signed-bitwise)

uint16_t integer::ntoh16(uint16_t v) { return ntohs(v); } //NOLINT(hicpp-signed-bitwise)
