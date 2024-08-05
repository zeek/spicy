// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utf8proc/utf8proc.h>

#include <hilti/rt/exception.h>
#include <hilti/rt/types/string.h>

using namespace hilti::rt;

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

Vector<std::string> string::split(std::string_view s) {
    auto xs = hilti::rt::split(s);

    Vector<std::string> result;
    result.reserve(xs.size());

    for ( auto&& v : xs )
        result.emplace_back(v);

    return result;
}

Vector<std::string> string::split(std::string_view s, std::string_view sep) {
    auto xs = hilti::rt::split(s, sep);

    Vector<std::string> result;
    result.reserve(xs.size());

    for ( auto&& v : xs )
        result.emplace_back(v);

    return result;
}

std::tuple<std::string, std::string> string::split1(const std::string& s) {
    auto pair = hilti::rt::split1(s);
    return {pair.first, pair.second};
}

std::tuple<std::string, std::string> string::split1(const std::string& s, const std::string& sep) {
    auto pair = hilti::rt::split1(s, sep);
    return {pair.first, pair.second};
}
