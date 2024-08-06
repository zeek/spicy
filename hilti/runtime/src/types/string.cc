// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/types/string.h"

#include <utf8proc/utf8proc.h>

#include <hilti/rt/exception.h>

namespace hilti::rt {

integer::safe<uint64_t> string::size(const std::string& s, DecodeErrorStrategy errors) {
    auto p = reinterpret_cast<const unsigned char*>(s.data());
    auto e = p + s.size();

    uint64_t len = 0;

    while ( p < e ) {
        utf8proc_int32_t cp;
        auto n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 ) {
            switch ( errors.value() ) {
                case DecodeErrorStrategy::IGNORE: break;
                case DecodeErrorStrategy::REPLACE: ++len; break;
                case DecodeErrorStrategy::STRICT: throw RuntimeError("illegal UTF8 sequence in string");
            }

            p += 1;
            continue;
        }

        ++len;
        p += n;
    }

    return len;
}

std::string string::upper(const std::string& s, DecodeErrorStrategy errors) {
    auto p = reinterpret_cast<const unsigned char*>(s.data());
    auto e = p + s.size();

    unsigned char buf[4];
    std::string rval;

    while ( p < e ) {
        utf8proc_int32_t cp;
        auto n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 ) {
            switch ( errors.value() ) {
                case DecodeErrorStrategy::IGNORE: break;
                case DecodeErrorStrategy::REPLACE: rval += "\ufffd"; break;
                case DecodeErrorStrategy::STRICT: throw RuntimeError("illegal UTF8 sequence in string");
            }

            p += 1;
            continue;
        }

        auto m = utf8proc_encode_char(utf8proc_toupper(cp), buf);
        rval += std::string(reinterpret_cast<char*>(buf), m);
        p += n;
    }

    return rval;
}

std::string string::lower(const std::string& s, DecodeErrorStrategy errors) {
    auto p = reinterpret_cast<const unsigned char*>(s.data());
    auto e = p + s.size();

    unsigned char buf[4];
    std::string rval;

    while ( p < e ) {
        utf8proc_int32_t cp;
        auto n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 ) {
            switch ( errors.value() ) {
                case DecodeErrorStrategy::IGNORE: break;
                case DecodeErrorStrategy::REPLACE: rval += "\ufffd"; break;
                case DecodeErrorStrategy::STRICT: throw RuntimeError("illegal UTF8 sequence in string");
            }

            p += 1;
            continue;
        }

        auto m = utf8proc_encode_char(utf8proc_tolower(cp), buf);
        rval += std::string(reinterpret_cast<char*>(buf), m);
        p += n;
    }

    return rval;
}

namespace detail::adl {

std::string to_string(const std::string& x, adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, true, true, true));
}

std::string to_string(std::string_view x, adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, true, true, true));
}

} // namespace detail::adl

} // namespace hilti::rt
