// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/types/bytes.h"

#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

std::tuple<bool, Bytes::const_iterator> Bytes::find(const Bytes& v, const const_iterator& n) const {
    if ( v.isEmpty() )
        return std::make_tuple(true, n ? n : begin());

    auto first = *v.begin();

    for ( auto i = const_iterator(n ? n : begin()); true; ++i ) {
        if ( i == end() )
            return std::make_tuple(false, i);

        if ( *i != first )
            continue;

        auto x = i;
        auto y = v.begin();

        for ( ;; ) {
            if ( x == end() )
                return std::make_tuple(false, i);

            if ( *x++ != *y++ )
                break;

            if ( y == v.end() )
                return std::make_tuple(true, i);
        }
    }
}

Bytes::Bytes(std::string s, bytes::Charset cs) : _control(std::make_shared<Base*>(static_cast<Base*>(this))) {
    switch ( cs ) {
        case bytes::Charset::UTF8:
            // Data is already in UTF-8, just need to copy it over.
            *this = std::move(s);
            return;

        case bytes::Charset::ASCII: {
            // Convert all bytes to 7-bit codepoints.
            std::for_each(s.begin(), s.end(), [](auto&& c) { c = (c >= 32 && c < 0x7f) ? static_cast<char>(c) : '?'; });

            *this = std::move(s);
            return;
        }

        case bytes::Charset::Undef: throw RuntimeError("unknown character set for encoding");
    }

    cannot_be_reached();
}

std::string Bytes::decode(bytes::Charset cs) const {
    switch ( cs ) {
        case bytes::Charset::UTF8:
            // Data is already in UTF-8, just need to copy it into a string.
            return str();

        case bytes::Charset::ASCII: {
            // Convert non-printable to the unicode replacement character.
            std::string s;
            for ( auto c : *this ) {
                if ( c >= 32 && c < 0x7f )
                    s += static_cast<char>(c);
                else
                    s += "\ufffd";
            }

            return s;
        }

        case bytes::Charset::Undef: throw RuntimeError("unknown character set for decoding");
    }

    cannot_be_reached();
}

Bytes Bytes::strip(const Bytes& set, bytes::Side side) const {
    switch ( side ) {
        case bytes::Side::Left: return Bytes(hilti::rt::ltrim(*this, set.str()));

        case bytes::Side::Right: return Bytes(hilti::rt::rtrim(*this, set.str()));

        case bytes::Side::Both: return Bytes(hilti::rt::trim(*this, set.str()));
    }

    cannot_be_reached();
}

Bytes Bytes::strip(bytes::Side side) const {
    switch ( side ) {
        case bytes::Side::Left: return Bytes(hilti::rt::ltrim(*this));

        case bytes::Side::Right: return Bytes(hilti::rt::rtrim(*this));

        case bytes::Side::Both: return Bytes(hilti::rt::trim(*this));
    }

    cannot_be_reached();
}

integer::safe<int64_t> Bytes::toInt(uint64_t base) const {
    int64_t x = 0;
    if ( hilti::rt::atoi_n(begin(), end(), base, &x) == end() )
        return x;

    throw RuntimeError("cannot parse bytes as signed integer");
}

integer::safe<uint64_t> Bytes::toUInt(uint64_t base) const {
    int64_t x = 0;
    if ( hilti::rt::atoi_n(begin(), end(), base, &x) == end() )
        return x;

    throw RuntimeError("cannot parse bytes as unsigned integer");
}

int64_t Bytes::toInt(ByteOrder byte_order) const {
    auto i = toUInt(byte_order);
    auto size_ = static_cast<uint64_t>(size());

    if ( i & (1U << (size_ * 8 - 1)) ) {
        if ( size() == 8 )
            return -(~i + 1);

        return -(i ^ ((1U << (size_ * 8)) - 1)) - 1;
    }

    return static_cast<int64_t>(i);
}

uint64_t Bytes::toUInt(ByteOrder byte_order) const {
    switch ( byte_order ) {
        case ByteOrder::Undef: throw RuntimeError("cannot convert value to undefined byte order");
        case ByteOrder::Host: return toInt(systemByteOrder());
        case ByteOrder::Little: [[fallthrough]];
        case ByteOrder::Network: [[fallthrough]];
        case ByteOrder::Big: break;
    }

    if ( size() > 8 )
        throw RuntimeError("more than max of 8 bytes for conversion to integer");

    uint64_t i = 0;

    for ( char c : *this )
        i = (i << 8U) | static_cast<uint8_t>(c);

    if ( byte_order == hilti::rt::ByteOrder::Little )
        i = integer::flip(i, size());

    return i;
}

Result<Bytes> Bytes::match(const RegExp& re, unsigned int group) const {
    auto groups = re.matchGroups(*this);

    if ( group >= groups.size() )
        return result::Error("no matches found");

    return groups.at(group);
}

void Bytes::append(const stream::View& view) { Base::append(view.data()); }

namespace hilti::rt::detail::adl {
std::string to_string(const Bytes& x, tag /*unused*/) { return fmt("b\"%s\"", escapeBytes(x.str(), true)); }

std::string to_string(const bytes::Charset& x, tag /*unused*/) {
    switch ( x ) {
        case bytes::Charset::ASCII: return "Charset::ASCII";
        case bytes::Charset::UTF8: return "Charset::UTF8";
        case bytes::Charset::Undef: return "Charset::Undef";
    }

    cannot_be_reached();
}

std::string to_string(const bytes::Side& x, tag /*unused*/) {
    switch ( x ) {
        case bytes::Side::Left: return "Side::Left";
        case bytes::Side::Right: return "Side::Right";
        case bytes::Side::Both: return "Side::Both";
    }

    cannot_be_reached();
}

} // namespace hilti::rt::detail::adl
