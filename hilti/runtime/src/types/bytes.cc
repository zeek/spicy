// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utf8proc/utf8proc.h>

#include <cstdlib>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

std::tuple<bool, Bytes::const_iterator> Bytes::find(const Bytes& v, const const_iterator& n) const {
    auto b = begin();

    if ( v.isEmpty() )
        return std::make_tuple(true, n ? n : b);

    auto bv = v.begin();
    auto first = *bv;

    for ( auto i = const_iterator(n ? n : b); true; ++i ) {
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

            if ( y == v.end() )
                return std::make_tuple(true, i);
        }
    }
}

Bytes::Bytes(std::string s, bytes::Charset cs, DecodeErrorStrategy errors) {
    switch ( cs.value() ) {
        case bytes::Charset::UTF8: {
            // Data supposedly is already in UTF-8, but let's validate it.
            std::string t;

            auto p = reinterpret_cast<const unsigned char*>(s.data());
            auto e = p + s.size();

            while ( p < e ) {
                utf8proc_int32_t cp;
                auto n = utf8proc_iterate(p, e - p, &cp);

                if ( n < 0 ) {
                    switch ( errors.value() ) {
                        case DecodeErrorStrategy::IGNORE: break;
                        case DecodeErrorStrategy::REPLACE: t += "\ufffd"; break;
                        case DecodeErrorStrategy::STRICT: throw RuntimeError("illegal UTF8 sequence in string");
                    }

                    p += 1;
                    continue;
                }

                t += std::string(reinterpret_cast<const char*>(p), n);
                p += n;
            }

            *this = std::move(t);
            return;
        }

        case bytes::Charset::ASCII: {
            std::string t;
            for ( const auto& c : s ) {
                if ( c >= 32 && c < 0x7f )
                    t += static_cast<char>(c);
                else {
                    switch ( errors.value() ) {
                        case DecodeErrorStrategy::IGNORE: break;
                        case DecodeErrorStrategy::REPLACE: t += '?'; break;
                        case DecodeErrorStrategy::STRICT: throw RuntimeError("illegal ASCII character in string");
                    }
                }
            }

            *this = std::move(t);
            return;
        }

        case bytes::Charset::Undef: throw RuntimeError("unknown character set for encoding");
    }

    cannot_be_reached();
}

std::string Bytes::decode(bytes::Charset cs, bytes::DecodeErrorStrategy errors) const {
    switch ( cs.value() ) {
        case bytes::Charset::UTF8:
            // Data is already in UTF-8, but let's validate it.
            return Bytes(str(), cs, errors).str();

        case bytes::Charset::ASCII: {
            std::string s;
            for ( auto c : str() ) {
                if ( c >= 32 && c < 0x7f )
                    s += c;
                else {
                    switch ( errors.value() ) {
                        case DecodeErrorStrategy::IGNORE: break;
                        case DecodeErrorStrategy::REPLACE: s += "?"; break;
                        case DecodeErrorStrategy::STRICT: throw RuntimeError("illegal ASCII character in string");
                    }
                }
            }

            return s;
        }

        case bytes::Charset::Undef: throw RuntimeError("unknown character set for decoding");
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
    auto i = toUInt(byte_order);
    auto size_ = static_cast<uint64_t>(size());

    if ( i & (1U << (size_ * 8 - 1)) ) {
        if ( size() == 8 )
            return static_cast<int64_t>(-(~i + 1));

        return static_cast<int64_t>(-(i ^ ((1U << (size_ * 8)) - 1)) - 1);
    }

    return static_cast<int64_t>(i);
}

uint64_t Bytes::toUInt(ByteOrder byte_order) const {
    switch ( byte_order.value() ) {
        case ByteOrder::Undef: throw RuntimeError("cannot convert value to undefined byte order");
        case ByteOrder::Host: return toInt(systemByteOrder());
        case ByteOrder::Little: [[fallthrough]];
        case ByteOrder::Network: [[fallthrough]];
        case ByteOrder::Big: break;
    }

    if ( auto size_ = size(); size_ > 8 )
        throw RuntimeError(fmt("more than max of 8 bytes for conversion to integer (have %" PRIu64 ")", size_));

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
std::string to_string(const Bytes& x, tag /*unused*/) { return fmt("b\"%s\"", escapeBytes(x.str(), true)); }

std::string to_string(const bytes::Charset& x, tag /*unused*/) {
    switch ( x.value() ) {
        case bytes::Charset::ASCII: return "Charset::ASCII";
        case bytes::Charset::UTF8: return "Charset::UTF8";
        case bytes::Charset::Undef: return "Charset::Undef";
    }

    cannot_be_reached();
}

std::string to_string(const bytes::DecodeErrorStrategy& x, tag /*unused*/) {
    switch ( x.value() ) {
        case bytes::DecodeErrorStrategy::IGNORE: return "DecodeErrorStrategy::IGNORE";
        case bytes::DecodeErrorStrategy::REPLACE: return "DecodeErrorStrategy::REPLACE";
        case bytes::DecodeErrorStrategy::STRICT: return "DecodeErrorStrategy::STRICT";
    }

    cannot_be_reached();
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
hilti::rt::bytes::Iterator::Iterator(typename B::size_type index, std::weak_ptr<const B*> control)
    : _control(std::move(control)), _index(index) {}
uint8_t hilti::rt::bytes::Iterator::operator*() const {
    if ( auto&& l = _control.lock() ) {
        auto&& data = static_cast<const B&>(**l);

        if ( _index >= data.size() )
            throw IndexError(fmt("index %s out of bounds", _index));

        return data[_index];
    }

    throw InvalidIterator("bound object has expired");
}
hilti::rt::bytes::Iterator& hilti::rt::bytes::Iterator::operator+=(uint64_t n) {
    _index += n;
    return *this;
}
hilti::rt::bytes::Iterator::operator bool() const { return static_cast<bool>(_control.lock()); }
hilti::rt::bytes::Iterator& hilti::rt::bytes::Iterator::operator++() {
    ++_index;
    return *this;
}
hilti::rt::bytes::Iterator hilti::rt::bytes::Iterator::operator++(int) {
    auto result = *this;
    ++_index;
    return result;
}
std::string hilti::rt::bytes::to_string(const Iterator& /* i */, rt::detail::adl::tag /*unused*/) {
    return "<bytes iterator>";
}
std::ostream& hilti::rt::bytes::operator<<(std::ostream& out, const Iterator& /* x */) {
    out << "<bytes iterator>";
    return out;
}
hilti::rt::Bytes::Bytes(Base&& str) : Base(std::move(str)) {}
hilti::rt::Bytes::Bytes(const Bytes& xs) : Base(xs) {}
hilti::rt::Bytes::Bytes(Bytes&& xs) noexcept : Base(std::move(xs)) {}
hilti::rt::Bytes& hilti::rt::Bytes::operator=(const Bytes& b) {
    if ( &b == this )
        return *this;

    invalidateIterators();
    this->Base::operator=(b);
    return *this;
}
hilti::rt::Bytes& hilti::rt::Bytes::operator=(Bytes&& b) noexcept {
    invalidateIterators();
    this->Base::operator=(std::move(b));
    return *this;
}
void hilti::rt::Bytes::append(const Bytes& d) { Base::append(d.str()); }
void hilti::rt::Bytes::append(const uint8_t x) { Base::append(1, static_cast<Base::value_type>(x)); }
const std::string& hilti::rt::Bytes::str() const& { return *this; }
std::string hilti::rt::Bytes::str() && { return std::move(*this); }
hilti::rt::Bytes::const_iterator hilti::rt::Bytes::begin() const { return const_iterator(0U, getControl()); }
hilti::rt::Bytes::const_iterator hilti::rt::Bytes::cbegin() const { return const_iterator(0U, getControl()); }
hilti::rt::Bytes::const_iterator hilti::rt::Bytes::end() const { return const_iterator(size(), getControl()); }
hilti::rt::Bytes::const_iterator hilti::rt::Bytes::cend() const { return const_iterator(size(), getControl()); }
hilti::rt::Bytes::const_iterator hilti::rt::Bytes::at(Offset o) const { return begin() + o; }
bool hilti::rt::Bytes::isEmpty() const { return empty(); }
hilti::rt::Bytes::size_type hilti::rt::Bytes::size() const { return static_cast<int64_t>(std::string::size()); }
hilti::rt::Bytes::const_iterator hilti::rt::Bytes::find(value_type b, const const_iterator& n) const {
    auto beg = begin();
    if ( auto i = Base::find(b, (n ? n - beg : 0)); i != Base::npos )
        return beg + i;
    else
        return end();
}
hilti::rt::Bytes hilti::rt::Bytes::sub(const const_iterator& from, const const_iterator& to) const {
    if ( from._control.lock() != to._control.lock() )
        throw InvalidArgument("start and end iterator cannot belong to different bytes");

    return sub(Offset(from - begin()), to._index);
}
hilti::rt::Bytes hilti::rt::Bytes::sub(const const_iterator& to) const { return sub(begin(), to); }
hilti::rt::Bytes hilti::rt::Bytes::sub(Offset from, Offset to) const {
    try {
        return {substr(from, to - from)};
    } catch ( const std::out_of_range& ) {
        throw OutOfRange(fmt("start index %s out of range for bytes with length %d", from, size()));
    }
}
hilti::rt::Bytes hilti::rt::Bytes::sub(Offset to) const { return sub(0, to); }
hilti::rt::Bytes hilti::rt::Bytes::extract(unsigned char* dst, uint64_t n) const {
    if ( n > size() )
        throw InvalidArgument("insufficient data in source");

    memcpy(dst, data(), n);
    return sub(n, std::string::npos);
}
bool hilti::rt::Bytes::startsWith(const Bytes& b) const { return hilti::rt::startsWith(*this, b); }
hilti::rt::Bytes hilti::rt::Bytes::upper(bytes::Charset cs, bytes::DecodeErrorStrategy errors) const {
    return Bytes(hilti::rt::string::upper(decode(cs, errors), errors), cs, errors);
}
hilti::rt::Bytes hilti::rt::Bytes::lower(bytes::Charset cs, bytes::DecodeErrorStrategy errors) const {
    return Bytes(hilti::rt::string::lower(decode(cs, errors), errors), cs, errors);
}
hilti::rt::Vector<Bytes> hilti::rt::Bytes::split() const {
    Vector<Bytes> x;
    for ( auto& v : hilti::rt::split(*this) )
        x.emplace_back(Bytes::Base(v));
    return x;
}
std::tuple<Bytes, Bytes> hilti::rt::Bytes::split1() const {
    auto p = hilti::rt::split1(str());
    return std::make_tuple(p.first, p.second);
}
hilti::rt::Vector<Bytes> hilti::rt::Bytes::split(const Bytes& sep) const {
    Vector<Bytes> x;
    for ( auto& v : hilti::rt::split(*this, sep) )
        x.push_back(Bytes::Base(v));
    return x;
}
std::tuple<Bytes, Bytes> hilti::rt::Bytes::split1(const Bytes& sep) const {
    auto p = hilti::rt::split1(str(), sep);
    return std::make_tuple(p.first, p.second);
}
hilti::rt::Time hilti::rt::Bytes::toTime(uint64_t base) const {
    auto ns = ! isEmpty() ? toUInt(base) * integer::safe<uint64_t>(1'000'000'000) : integer::safe<uint64_t>(0);
    return Time(ns, Time::NanosecondTag());
}
hilti::rt::Time hilti::rt::Bytes::toTime(hilti::rt::ByteOrder byte_order) const {
    return Time(toUInt(byte_order) * integer::safe<uint64_t>(1'000'000'000), Time::NanosecondTag());
}
const hilti::rt::Bytes::C& hilti::rt::Bytes::getControl() const {
    if ( ! _control )
        _control = std::make_shared<const Base*>(static_cast<const Base*>(this));

    return _control;
}
void hilti::rt::Bytes::invalidateIterators() { _control.reset(); }
std::ostream& hilti::rt::operator<<(std::ostream& out, const Bytes& x) {
    out << escapeBytes(x.str(), false);
    return out;
}
