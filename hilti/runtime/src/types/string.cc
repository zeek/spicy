// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utf8.h>
#include <utf8proc/utf8proc.h>

#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

integer::safe<uint64_t> string::size(const std::string& s, unicode::DecodeErrorStrategy errors) {
    auto p = s.begin();
    auto e = s.end();

    uint64_t len = 0;

    while ( p < e ) {
        try {
            // `utf8::next` is for iterating UTF-8 strings.
            utf8::next(p, s.end());
            ++len;
        } catch ( const utf8::invalid_utf8& ) {
            switch ( errors.value() ) {
                case unicode::DecodeErrorStrategy::STRICT: throw RuntimeError("illegal UTF8 sequence in string");
                case unicode::DecodeErrorStrategy::REPLACE: {
                    ++len;
                }
                    [[fallthrough]];
                case unicode::DecodeErrorStrategy::IGNORE: {
                    ++p;
                    break;
                }
            }
        }
    }

    return len;
}

std::string string::upper(std::string_view s, unicode::DecodeErrorStrategy errors) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const auto* e = p + s.size();

    unsigned char buf[4];
    std::string rval;

    while ( p < e ) {
        utf8proc_int32_t cp;
        auto n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 ) {
            switch ( errors.value() ) {
                case unicode::DecodeErrorStrategy::IGNORE: break;
                case unicode::DecodeErrorStrategy::REPLACE: utf8::append(unicode::REPLACEMENT_CHARACTER, rval); break;
                case unicode::DecodeErrorStrategy::STRICT: throw RuntimeError("illegal UTF8 sequence in string");
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

std::string string::lower(std::string_view s, unicode::DecodeErrorStrategy errors) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const auto* e = p + s.size();

    unsigned char buf[4];
    std::string rval;

    while ( p < e ) {
        utf8proc_int32_t cp;
        auto n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 ) {
            switch ( errors.value() ) {
                case unicode::DecodeErrorStrategy::IGNORE: break;
                case unicode::DecodeErrorStrategy::REPLACE: utf8::append(unicode::REPLACEMENT_CHARACTER, rval); break;
                case unicode::DecodeErrorStrategy::STRICT: throw RuntimeError("illegal UTF8 sequence in string");
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

Tuple<std::string, std::string> string::split1(const std::string& s) {
    auto pair = hilti::rt::split1(s);
    return tuple::make(std::move(pair.first), std::move(pair.second));
}

Tuple<std::string, std::string> string::split1(const std::string& s, const std::string& sep) {
    auto pair = hilti::rt::split1(s, sep);
    return tuple::make(std::move(pair.first), std::move(pair.second));
}

Bytes string::encode(std::string s, unicode::Charset cs, unicode::DecodeErrorStrategy errors) try {
    if ( s.empty() )
        return {std::move(s)};

    switch ( cs.value() ) {
        case unicode::Charset::UTF8: {
            // HILTI `string` is always UTF-8, but we could be invoked with raw bags of bytes here as well, so validate.
            std::string t;

            auto p = s.begin();
            auto e = s.end();

            while ( p < e ) {
                try {
                    auto cp = utf8::next(p, e);
                    utf8::append(cp, t);
                } catch ( const utf8::invalid_utf8& ) {
                    switch ( errors.value() ) {
                        case unicode::DecodeErrorStrategy::IGNORE: break;
                        case unicode::DecodeErrorStrategy::REPLACE: {
                            utf8::append(unicode::REPLACEMENT_CHARACTER, t);
                            break;
                        }
                        case unicode::DecodeErrorStrategy::STRICT:
                            throw RuntimeError("illegal UTF8 sequence in string");
                    }

                    ++p;
                }
            }

            return Bytes(std::move(t));
        }

        case unicode::Charset::UTF16BE: [[fallthrough]];
        case unicode::Charset::UTF16LE: {
            // HILTI `string` is always UTF-8, but we could be invoked with raw bags of bytes here as well, so validate.
            auto t8 = string::encode(std::move(s), unicode::Charset::UTF8, errors).str();

            auto t = utf8::utf8to16(t8);

            std::string result;
            result.reserve(t.size() * 2);
            for ( auto c : t ) {
                auto* xs = reinterpret_cast<char*>(&c);

                switch ( cs.value() ) {
                    case unicode::Charset::UTF16LE: {
                        result += xs[0];
                        result += xs[1];
                        break;
                    }
                    case unicode::Charset::UTF16BE: {
                        result += xs[1];
                        result += xs[0];
                        break;
                    }
                }
            }

            return {std::move(result)};
        }

        case unicode::Charset::ASCII: {
            std::string t;
            for ( const auto& c : s ) {
                if ( c >= 32 && c < 0x7f )
                    t += static_cast<char>(c);
                else {
                    switch ( errors.value() ) {
                        case unicode::DecodeErrorStrategy::IGNORE: break;
                        case unicode::DecodeErrorStrategy::REPLACE: t += '?'; break;
                        case unicode::DecodeErrorStrategy::STRICT:
                            throw RuntimeError("illegal ASCII character in string");
                    }
                }
            }

            return Bytes(std::move(t));
        }

        case unicode::Charset::Undef: throw RuntimeError("unknown character set for encoding");
    }

    cannot_be_reached();
} catch ( const RuntimeError& ) {
    // Directly propagate already correctly wrapped exceptions.
    throw;
} catch ( ... ) {
    // Throw a new `RuntimeError` for any other exception which has made it out of the function.
    throw RuntimeError("could not encode string");
}
