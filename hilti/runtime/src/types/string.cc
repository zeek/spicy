// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/types/string.h"

#include <utf8proc/utf8proc.h>

#include <hilti/rt/exception.h>

using namespace hilti::rt;

size_t string::size(const std::string& s) {
    auto p = reinterpret_cast<const unsigned char*>(s.data());
    auto e = p + s.size();

    size_t len = 0;

    while ( p < e ) {
        utf8proc_int32_t cp;
        auto n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 )
            throw RuntimeError("illegal UTF8 sequence in string");

        ++len;
        p += n;
    }

    return len;
}

std::string string::upper(const std::string& s) {
    auto p = reinterpret_cast<const unsigned char*>(s.data());
    auto e = p + s.size();

    unsigned char buf[4];
    std::string rval;

    while ( p < e ) {
        utf8proc_int32_t cp;
        auto n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 )
            throw RuntimeError("illegal UTF8 sequence in string");

        auto m = utf8proc_encode_char(utf8proc_toupper(cp), buf);
        rval += std::string(reinterpret_cast<char*>(buf), m);
        p += n;
    }

    return rval;
}

std::string string::lower(const std::string& s) {
    auto p = reinterpret_cast<const unsigned char*>(s.data());
    auto e = p + s.size();

    unsigned char buf[4];
    std::string rval;

    while ( p < e ) {
        utf8proc_int32_t cp;
        auto n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 )
            throw RuntimeError("illegal UTF8 sequence in string");

        auto m = utf8proc_encode_char(utf8proc_tolower(cp), buf);
        rval += std::string(reinterpret_cast<char*>(buf), m);
        p += n;
    }

    return rval;
}
