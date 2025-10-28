// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utf8.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/unicode.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

namespace {

// An iterator over `char16_t` which can adjust the byte order.
struct U16Iterator {
    // Most of this is boilerplate.
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = const char16_t;
    using pointer = value_type*;
    using reference = value_type&;

    pointer cur = nullptr;

    U16Iterator& operator++() {
        ++cur;
        return *this;
    }

    U16Iterator operator++(int) {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

    friend bool operator==(const U16Iterator& a, const U16Iterator& b) { return a.cur == b.cur; };
    friend bool operator!=(const U16Iterator& a, const U16Iterator& b) { return ! (a == b); };

    // Implementation of custom behavior below.
    enum Order { LE, BE, Detected };

    U16Iterator(pointer ptr, Order order) : cur(ptr), order(order) {}

    Order order;

    auto operator*() const {
        switch ( order ) {
            case Detected: [[fallthrough]];
            case LE: return *cur;
            case BE: {
                auto r = *cur;

                char* xs = reinterpret_cast<char*>(&r);
                std::swap(xs[0], xs[1]);

                return r;
            }
        }

        cannot_be_reached();
    }
};

} // namespace

Tuple<bool, Bytes::const_iterator> Bytes::find(const Bytes& needle, const const_iterator& start) const {
    auto b = begin();

    if ( needle.isEmpty() )
        return tuple::make(true, start ? start : b);

    auto bv = needle.unsafeBegin();
    auto first = *bv;

    for ( auto i = const_iterator(start ? start : b); true; ++i ) {
        if ( i == end() )
            return tuple::make(false, i);

        if ( *i != first )
            continue;

        auto x = i;
        auto y = bv;

        for ( ;; ) {
            if ( x == end() )
                return tuple::make(false, i);

            if ( *x++ != *y++ )
                break;

            if ( y == needle.unsafeEnd() )
                return tuple::make(true, i);
        }
    }
}

std::string Bytes::decode(unicode::Charset cs, unicode::DecodeErrorStrategy errors) const try {
    if ( Base::empty() )
        return "";

    switch ( cs.value() ) {
        case unicode::Charset::UTF8: {
            std::string t;

            auto p = Base::begin();
            auto e = Base::end();

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

            return t;
        }

        case unicode::Charset::UTF16BE: [[fallthrough]];
        case unicode::Charset::UTF16LE: {
            if ( Base::size() % 2 != 0 ) {
                switch ( errors.value() ) {
                    case unicode::DecodeErrorStrategy::STRICT: throw RuntimeError("illegal UTF16 character in string");
                    case unicode::DecodeErrorStrategy::IGNORE: {
                        // Ignore the last byte.
                        return Bytes(str().substr(0, Base::size() / 2 * 2)).decode(cs, errors);
                    }
                    case unicode::DecodeErrorStrategy::REPLACE: {
                        // Convert everything but the last byte, and append replacement.
                        auto dec = Bytes(str().substr(0, Base::size() / 2 * 2)).decode(cs, errors);
                        utf8::append(unicode::REPLACEMENT_CHARACTER, dec);
                        return dec;
                    }
                }
            }

            // We can assume an even number of bytes.

            std::u16string t;

            // utfcpp expects to iterate a `u16string` or `u16string_view`.
            auto v16 = std::u16string_view{reinterpret_cast<const char16_t*>(Base::data()), Base::size() / 2};

            // We prefer to use the byte order from a BOM if present. If none is found use the passed byte order.
            U16Iterator::Order order = U16Iterator::Detected;
            if ( ! startsWith("\xFF\xFE") && ! startsWith("\xFE\xFF") )
                order = (cs.value() == unicode::Charset::UTF16LE ? U16Iterator::LE : U16Iterator::BE);

            auto p = U16Iterator(v16.begin(), order);
            auto e = U16Iterator(v16.end(), order);

            while ( p != e ) {
                try {
                    auto cp = utf8::next16(p, e);
                    utf8::append16(cp, t);
                } catch ( const utf8::invalid_utf16& ) {
                    switch ( errors.value() ) {
                        case unicode::DecodeErrorStrategy::IGNORE: break;
                        case unicode::DecodeErrorStrategy::REPLACE:
                            utf8::append16(unicode::REPLACEMENT_CHARACTER, t);
                            break;
                        case unicode::DecodeErrorStrategy::STRICT:
                            throw RuntimeError("illegal UTF16 character in string");
                    }

                    ++p;
                }
            }

            return {utf8::utf16to8(t)};
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
} catch ( const RuntimeError& ) {
    // Directly propagate already correctly wrapped exceptions.
    throw;
} catch ( ... ) {
    // Throw a new `RuntimeError` for any other exception which has made it out of the function.
    throw RuntimeError("could not decode bytes");
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

Bytes Bytes::upper(unicode::Charset cs, unicode::DecodeErrorStrategy errors) const {
    return string::encode(string::upper(decode(cs, errors), errors), cs, errors);
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

integer::safe<int64_t> Bytes::toInt(ByteOrder byte_order) const {
    auto i = toUInt(byte_order).Ref(); // throws on size == 0 or size > 8
    auto size_ = static_cast<uint64_t>(size());

    if ( i & (UINT64_C(1) << (size_ * 8 - 1)) ) {
        if ( size() == 8 )
            return static_cast<int64_t>(-(~i + 1));

        return static_cast<int64_t>(-(i ^ ((UINT64_C(1) << (size_ * 8)) - 1)) - 1);
    }

    return static_cast<int64_t>(i);
}

integer::safe<uint64_t> Bytes::toUInt(ByteOrder byte_order) const {
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

Bytes Bytes::lower(unicode::Charset cs, unicode::DecodeErrorStrategy errors) const {
    return string::encode(string::lower(decode(cs, errors), errors), cs, errors);
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
