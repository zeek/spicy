// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utf8proc/utf8proc.h>

#include <cstdint>
#include <cstdlib>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

std::tuple<bool, Bytes::const_iterator> Bytes::find(const Bytes& needle, const const_iterator& start) const {
    auto b = begin();

    if ( needle.isEmpty() )
        return std::make_tuple(true, start ? start : b);

    auto bv = needle.unsafeBegin();
    auto first = *bv;

    for ( auto i = const_iterator(start ? start : b); true; ++i ) {
        if ( i == end() )
            return std::make_tuple(false, i);

        if ( *i != first )
            continue;

        auto x = i;
        auto y = bv;

        for ( ;; ) {
            if ( x == end() )
                return std::make_tuple(false, i);

            if ( *x++ != *y++ )
                break;

            if ( y == needle.unsafeEnd() )
                return std::make_tuple(true, i);
        }
    }
}

std::string Bytes::decode(unicode::Charset cs, unicode::DecodeErrorStrategy errors) const {
    switch ( cs.value() ) {
        case unicode::Charset::UTF8: {
            std::string t;

            auto p = reinterpret_cast<const unsigned char*>(Base::data());
            auto e = p + Base::size();

            while ( p < e ) {
                utf8proc_int32_t cp;
                auto n = utf8proc_iterate(p, e - p, &cp);

                if ( n < 0 ) {
                    switch ( errors.value() ) {
                        case unicode::DecodeErrorStrategy::IGNORE: break;
                        case unicode::DecodeErrorStrategy::REPLACE: t += "\ufffd"; break;
                        case unicode::DecodeErrorStrategy::STRICT:
                            throw RuntimeError("illegal UTF8 sequence in string");
                    }

                    p += 1;
                    continue;
                }

                t += std::string(reinterpret_cast<const char*>(p), n);
                p += n;
            }

            return {t};
        }

        case unicode::Charset::ASCII: {
            std::string s;
            for ( auto c : str() ) {
                if ( c >= 32 && c < 0x7f )
                    s += c;
                else {
                    switch ( errors.value() ) {
                        case unicode::DecodeErrorStrategy::IGNORE: break;
                        case unicode::DecodeErrorStrategy::REPLACE: s += "?"; break;
                        case unicode::DecodeErrorStrategy::STRICT:
                            throw RuntimeError("illegal ASCII character in string");
                    }
                }
            }

            return s;
        }

        case unicode::Charset::Undef: throw RuntimeError("unknown character set for decoding");
    }

    cannot_be_reached();
}

Bytes Bytes::strip(const Bytes& set, bytes::Side side) const {
    switch ( side.value() ) {
        case bytes::Side::Left: return Bytes(hilti::rt::ltrim(*this, set.str()));

        case bytes::Side::Right: return Bytes(hilti::rt::rtrim(*this, set.str()));

        case bytes::Side::Both: return Bytes(hilti::rt::trim(*this, set.str()));
    }

    cannot_be_reached();
}

Bytes Bytes::strip(bytes::Side side) const {
    switch ( side.value() ) {
        case bytes::Side::Left: return Bytes(hilti::rt::ltrim(*this));

        case bytes::Side::Right: return Bytes(hilti::rt::rtrim(*this));

        case bytes::Side::Both: return Bytes(hilti::rt::trim(*this));
    }

    cannot_be_reached();
}

integer::safe<int64_t> Bytes::toInt(uint64_t base) const {
    int64_t x = 0;
    if ( hilti::rt::atoi_n(str().begin(), str().end(), base, &x) == str().end() )
        return x;

    throw RuntimeError("cannot parse bytes as signed integer");
}

integer::safe<uint64_t> Bytes::toUInt(uint64_t base) const {
    int64_t x = 0;
    if ( hilti::rt::atoi_n(str().begin(), str().end(), base, &x) == str().end() )
        return x;

    throw RuntimeError("cannot parse bytes as unsigned integer");
}

int64_t Bytes::toInt(ByteOrder byte_order) const {
    auto i = toUInt(byte_order); // throws on size == 0 or size > 8
    auto size_ = static_cast<uint64_t>(size());

    if ( i & (UINT64_C(1) << (size_ * 8 - 1)) ) {
        if ( size() == 8 )
            return static_cast<int64_t>(-(~i + 1));

        return static_cast<int64_t>(-(i ^ ((UINT64_C(1) << (size_ * 8)) - 1)) - 1);
    }

    return static_cast<int64_t>(i);
}

uint64_t Bytes::toUInt(ByteOrder byte_order) const {
    switch ( byte_order.value() ) {
        case ByteOrder::Undef: throw InvalidArgument("cannot convert value to undefined byte order");
        case ByteOrder::Host: return toInt(systemByteOrder());
        case ByteOrder::Little: [[fallthrough]];
        case ByteOrder::Network: [[fallthrough]];
        case ByteOrder::Big: break;
    }

    if ( isEmpty() )
        throw InvalidValue("not enough bytes for conversion to integer");

    if ( auto size_ = size(); size_ > 8 )
        throw InvalidValue(fmt("more than max of 8 bytes for conversion to integer (have %" PRIu64 ")", size_));

    uint64_t i = 0;

    for ( auto c : str() )
        i = (i << 8U) | static_cast<uint8_t>(c);

    if ( byte_order == hilti::rt::ByteOrder::Little )
        i = integer::flip(i, size());

    return i;
}

double Bytes::toReal() const {
    // Ensure there are no null bytes inside our data, so that we can call strtod().
    if ( Base::find('\0') != Base::npos )
        throw InvalidValue("cannot parse real value: null byte in data");

    const char* cstr = Base::c_str();
    char* endp = nullptr;

    errno = 0;
    auto d = strtod_l(cstr, &endp, *detail::globalState()->c_locale);
    if ( endp == cstr || *endp != '\0' || (d == HUGE_VAL && errno == ERANGE) ) {
        errno = 0;
        throw InvalidValue(fmt("cannot parse real value: '%s'", cstr));
    }

    return d;
}

Result<Bytes> Bytes::match(const RegExp& re, unsigned int group) const {
    auto groups = re.matchGroups(*this);

    if ( group >= groups.size() )
        return result::Error("no matches found");

    return groups.at(group);
}

void Bytes::append(const stream::View& view) {
    reserve(size() + view.size());
    for ( auto block = view.firstBlock(); block; block = view.nextBlock(block) )
        Base::append(reinterpret_cast<const char*>(block->start), block->size);
}

namespace hilti::rt::detail::adl {
std::string to_string(const Bytes& x, tag /*unused*/) {
    return fmt("b\"%s\"", escapeBytes(x.str(), render_style::Bytes::EscapeQuotes));
}

std::string to_string(const bytes::Side& x, tag /*unused*/) {
    switch ( x.value() ) {
        case bytes::Side::Left: return "Side::Left";
        case bytes::Side::Right: return "Side::Right";
        case bytes::Side::Both: return "Side::Both";
    }

    cannot_be_reached();
}

} // namespace hilti::rt::detail::adl
