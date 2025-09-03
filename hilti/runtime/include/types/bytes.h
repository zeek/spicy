// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/json-fwd.h>
#include <hilti/rt/result.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/tuple.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/unicode.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

class Bytes;
class RegExp;

namespace stream {
class View;
}

namespace bytes {

/** For Bytes::Strip, which side to strip from. */
HILTI_RT_ENUM_WITH_DEFAULT(Side, Left,
                           Left,  // left side
                           Right, // right side
                           Both   // left and right side
);

/**
 * Safe bytes iterator traversing the content of an instance.
 *
 * Unlike the STL-style iterators, this iterator protects against the bytes
 * instance being no longer available by throwing an `InvalidIterator`
 * exception if it's still dereferenced. It will also catch attempts to
 * dereference iterators that remain outside of the current valid range of the
 * underlying bytes instance, throwing an `IndexError` exception in that case.
 * However, operations that only move the iterator will succeed even for
 * out-of-range positions. That includes advancing an iterator beyond the end
 * of the content.
 */
class SafeIterator {
    using B = std::string;
    using difference_type = B::const_iterator::difference_type;

    using Control = control::Reference<B, InvalidIterator>;
    Control _control;
    typename integer::safe<std::uint64_t> _index = 0;

public:
    SafeIterator() = default;

    SafeIterator(typename B::size_type index, Control control) : _control(std::move(control)), _index(index) {}

    integer::safe<uint8_t> operator*() const {
        auto&& data = _control.get();

        if ( _index >= data.size() )
            throw IndexError(fmt("index %s out of bounds", _index));

        return static_cast<uint8_t>(data[_index]);
    }

    template<typename T>
    auto& operator+=(const hilti::rt::integer::safe<T>& n) {
        return *this += n.Ref();
    }

    auto& operator+=(uint64_t n) {
        _index += n;
        return *this;
    }

    template<typename T>
    auto operator+(const hilti::rt::integer::safe<T>& n) const {
        return *this + n.Ref();
    }

    template<typename T>
    auto operator+(const T& n) const {
        return SafeIterator{_index + n, _control};
    }

    explicit operator bool() const { return _control.isValid(); }

    auto& operator++() {
        ++_index;
        return *this;
    }

    auto operator++(int) {
        auto result = *this;
        ++_index;
        return result;
    }

    friend auto operator==(const SafeIterator& a, const SafeIterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index == b._index;
    }

    friend bool operator!=(const SafeIterator& a, const SafeIterator& b) { return ! (a == b); }

    friend auto operator<(const SafeIterator& a, const SafeIterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index < b._index;
    }

    friend auto operator<=(const SafeIterator& a, const SafeIterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index <= b._index;
    }

    friend auto operator>(const SafeIterator& a, const SafeIterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index > b._index;
    }

    friend auto operator>=(const SafeIterator& a, const SafeIterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot compare iterators into different bytes");
        return a._index >= b._index;
    }

    friend difference_type operator-(const SafeIterator& a, const SafeIterator& b) {
        if ( a._control != b._control )
            throw InvalidArgument("cannot perform arithmetic with iterators into different bytes");
        return a._index - b._index;
    }

    friend class ::hilti::rt::Bytes;
};

inline std::string to_string(const SafeIterator& /* i */, rt::detail::adl::tag /*unused*/) {
    return "<bytes iterator>";
}

inline std::ostream& operator<<(std::ostream& out, const SafeIterator& /* x */) {
    out << "<bytes iterator>";
    return out;
}

namespace detail {
/**
 * Unsafe bytes iterator for internal usage. Unlike *SafeConstIterator*, this
 * version is not safe against the underlying bytes instances
 * disappearing or potentially even just changing; it will not catch that and
 * likely causes crashes on access. It also does not perform any
 * bounds-checking. When using this, one needs to ensure that the bytes
 * instance will remain valid & unchanged for long as the iterator remains
 * alive. In return, this iterator is more efficient than the
 * `SafeConstIterator`.
 */
class UnsafeConstIterator {
    using I = std::string::const_iterator;

    I _i;

public:
    UnsafeConstIterator() = default;
    UnsafeConstIterator(I i) : _i(i) {}

    uint8_t operator*() const { return static_cast<uint8_t>(*_i); }

    template<typename T>
    auto& operator+=(const T& n) {
        return *this += n;
    }

    auto& operator+=(uint64_t n) {
        _i += static_cast<I::difference_type>(n);
        return *this;
    }

    template<typename T>
    auto operator+(const T& n) const {
        return *this + n;
    }

    auto& operator++() {
        ++_i;
        return *this;
    }

    auto operator++(int) {
        auto result = *this;
        ++_i;
        return result;
    }

    friend auto operator==(const UnsafeConstIterator& a, const UnsafeConstIterator& b) { return a._i == b._i; }
    friend bool operator!=(const UnsafeConstIterator& a, const UnsafeConstIterator& b) { return ! (a == b); }
    friend auto operator<(const UnsafeConstIterator& a, const UnsafeConstIterator& b) { return a._i < b._i; }
    friend auto operator<=(const UnsafeConstIterator& a, const UnsafeConstIterator& b) { return a._i <= b._i; }
    friend auto operator>(const UnsafeConstIterator& a, const UnsafeConstIterator& b) { return a._i > b._i; }
    friend auto operator>=(const UnsafeConstIterator& a, const UnsafeConstIterator& b) { return a._i >= b._i; }
    friend auto operator-(const UnsafeConstIterator& a, const UnsafeConstIterator& b) { return a._i - b._i; }
};

inline std::string to_string(const UnsafeConstIterator& /* i */, rt::detail::adl::tag /*unused*/) {
    return "<bytes iterator>";
}

inline std::ostream& operator<<(std::ostream& out, const UnsafeConstIterator& /* x */) {
    out << "<bytes iterator>";
    return out;
}

} // namespace detail

} // namespace bytes

/** HILTI's `Bytes` is a `std::string`-like type for wrapping raw bytes with
 * additional safety guarantees.
 *
 * If not otherwise specified, member functions have the semantics of
 * `std::string` member functions.
 */
class Bytes : protected std::string {
public:
    using Base = std::string;
    using const_iterator = bytes::SafeIterator;
    using unsafe_const_iterator = bytes::detail::UnsafeConstIterator;
    using Base::const_reference;
    using Base::reference;
    using Offset = uint64_t;
    using size_type = integer::safe<uint64_t>;

    using Base::Base;
    using Base::data;

    using C = std::shared_ptr<const Base*>;

    /**
     * Creates a bytes instance from a raw string representation.
     */
    Bytes(Base s) : Base(std::move(s)) {}

    Bytes(const Bytes& xs) : Base(xs) {}
    Bytes(Bytes&& xs) noexcept : Base(std::move(xs)) {}

    /** Replaces the contents of this `Bytes` with another `Bytes`.
     *
     * This function invalidates all iterators.
     *
     * @param b the `Bytes` to assign
     * @return a reference to the changed `Bytes`
     */
    Bytes& operator=(const Bytes& b) {
        if ( &b == this )
            return *this;

        _invalidateIterators();
        this->Base::operator=(b);
        return *this;
    }

    /** Replaces the contents of this `Bytes` with another `Bytes`.
     *
     * This function invalidates all iterators.
     *
     * @param b the `Bytes` to assign
     * @return a reference to the changed `Bytes`
     */
    Bytes& operator=(Bytes&& b) noexcept {
        _invalidateIterators();
        this->Base::operator=(std::move(b));
        return *this;
    }

    /** Appends the contents of a stream view to the data. */
    void append(const Bytes& d) { Base::append(d.str()); }

    /** Appends the contents of a stream view to the data. */
    void append(const stream::View& view);

    /** Appends a single byte the data. */
    void append(const uint8_t x) { Base::append(1, static_cast<Base::value_type>(x)); }

    /** Returns the bytes' data as a string instance. */
    const std::string& str() const& { return *this; }

    /** Returns the bytes' data as a string instance. */
    std::string str() && { return std::move(*this); }

    /** Returns an iterator representing the first byte of the instance. */
    const_iterator begin() const { return const_iterator(0U, _control); }

    /** Same as `begin()`, just for compatibility with std types. */
    const_iterator cbegin() const { return const_iterator(0U, _control); }

    /**
     * Returns an unchecked (but fast) iterator representing the first byte of
     * the instance.
     */
    auto unsafeBegin() const { return unsafe_const_iterator(str().begin()); }

    /** Returns an iterator representing the end of the instance. */
    const_iterator end() const { return const_iterator(size(), _control); }

    /** Same as `end()`, just for compatibility with std types. */
    const_iterator cend() const { return const_iterator(size(), _control); }

    /**
     * Returns an unchecked (but fast) iterator representing the end of the
     * instance.
     */
    auto unsafeEnd() const { return unsafe_const_iterator(str().end()); }

    /** Returns an iterator referring to the given offset. */
    const_iterator at(Offset o) const { return begin() + o; }

    /** Returns true if the data's size is zero. */
    bool isEmpty() const { return empty(); }

    /** Returns the size of instance in bytes. */
    size_type size() const { return static_cast<int64_t>(std::string::size()); }

    /**
     * Returns the position of the first occurrence of a byte.
     *
     * @param needle byte to search
     * @param start optional starting point, which must be inside the same instance
     */
    const_iterator find(value_type needle, const const_iterator& start = const_iterator()) const {
        auto beg = begin();
        if ( auto i = Base::find(needle, (start ? start - beg : 0)); i != Base::npos )
            return beg + i;
        else
            return end();
    }

    /**
     * Returns the position of the first occurrence of a range of bytes
     *
     * @param needle bytes to search
     * @param start optional starting point, which must be inside the same instance
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st bytes;
     * if no, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*.
     */
    Tuple<bool, const_iterator> find(const Bytes& needle, const const_iterator& start = const_iterator()) const;

    /**
     * Extracts a subrange of bytes.
     *
     * @param from iterator pointing to start of subrange
     * @param to iterator pointing to just beyond subrange
     * @return a `Bytes` instance for the subrange
     */
    Bytes sub(const const_iterator& from, const const_iterator& to) const {
        if ( from._control != to._control )
            throw InvalidArgument("start and end iterator cannot belong to different bytes");

        return sub(Offset(from - begin()), to._index);
    }

    /**
     * Extracts a subrange of bytes from the beginning.
     *
     * @param to iterator pointing to just beyond subrange
     * @return a `Bytes` instance for the subrange
     */
    Bytes sub(const const_iterator& to) const { return sub(begin(), to); }

    /**
     * Extracts a subrange of bytes.
     *
     * @param offset of start of subrage
     * @param offset of one byeond end of subrage
     * @return a `Bytes` instance for the subrange
     */
    Bytes sub(Offset from, Offset to) const {
        try {
            return {substr(from, to - from)};
        } catch ( const std::out_of_range& ) {
            throw OutOfRange(fmt("start index %s out of range for bytes with length %d", from, size()));
        }
    }

    /**
     * Extracts a subrange of bytes from the beginning.
     *
     * @param to offset of one beyond end of subrange
     * @return a `Bytes` instance for the subrange
     */
    Bytes sub(Offset to) const { return sub(0, to); }

    /**
     * Extracts a fixed number of bytes from the data
     *
     * @param dst array to writes bytes into
     * @param n number of bytes to extract
     * @return new bytes instance that has the first *N* bytes removed.
     */
    Bytes extract(unsigned char* dst, uint64_t n) const {
        if ( n > size() )
            throw InvalidArgument("insufficient data in source");

        memcpy(dst, data(), n);
        return sub(n, std::string::npos);
    }

    /**
     * Decodes the binary data into a string assuming its encoded in a
     * specified character set.
     *
     * @param cs character set to assume the binary data to be encoded in
     * @param errors how to handle errors when decoding the data
     * @return UTF8 string
     */
    std::string decode(unicode::Charset cs,
                       unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE) const;

    /** Returns true if the data begins with a given, other bytes instance. */
    bool startsWith(const Bytes& prefix) const { return hilti::rt::startsWith(*this, prefix); }

    /** Returns true if the data begins with a given, other bytes instance. */
    bool endsWith(const Bytes& suffix) const { return hilti::rt::endsWith(*this, suffix); }

    /**
     * Returns an upper-case version of the instance. This internally first
     * decodes the data assuming a specified character set, then encodes it
     * back afterwards.
     *
     * @param cs character set for decoding/encoding
     * @param errors how to handle errors when decoding/encoding the data
     * @return an upper case version of the instance
     */
    Bytes upper(unicode::Charset cs, unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE) const;

    /**
     * Returns an upper-case version of the instance.
     *
     * @param cs character set for decoding/encoding
     * @param errors how to handle errors when decoding/encoding the data
     * @return a lower case version of the instance
     */
    Bytes lower(unicode::Charset cs, unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE) const;

    /**
     * Removes leading and/or trailing sequences of all characters of a set
     * from the bytes instance.
     *
     * @param side side of bytes instance to be stripped.
     * @param set characters to remove; removes all whitespace if empty
     * @return a stripped version of the instance
     */
    Bytes strip(const Bytes& set, bytes::Side side = bytes::Side::Both) const;

    /**
     * Removes leading and/or trailing sequences of white space from the
     * bytes instance.
     *
     * @param side side of bytes instance to be stripped.
     * @return a stripped version of the instance
     */
    Bytes strip(bytes::Side side = bytes::Side::Both) const;

    /** Splits the data at sequences of whitespace, returning the parts. */
    Vector<Bytes> split() const {
        Vector<Bytes> x;
        for ( auto& v : hilti::rt::split(*this) )
            x.emplace_back(Bytes::Base(v));
        return x;
    }

    /**
     * Splits the data (only) at the first sequence of whitespace, returning
     * the two parts.
     */
    Tuple<Bytes, Bytes> split1() const {
        auto p = hilti::rt::split1(str());
        return {p.first, p.second};
    }

    /** Splits the data at occurrences of a separator, returning the parts. */
    Vector<Bytes> split(const Bytes& sep) const {
        Vector<Bytes> x;
        for ( auto& v : hilti::rt::split(*this, sep) )
            x.push_back(Bytes::Base(v));
        return x;
    }

    /**
     * Splits the data (only) at the first occurrence of a separator,
     * returning the two parts.
     *
     * @param sep `Bytes` sequence to split at
     * @return a tuple of head and tail of the split instance
     */
    Tuple<Bytes, Bytes> split1(const Bytes& sep) const {
        auto p = hilti::rt::split1(str(), sep);
        return {p.first, p.second};
    }

    /**
     * Returns the concatenation of all elements in the *parts* list rendered
     * as printable strings and separated by the bytes value providing this
     * method.
     */
    template<typename T>
    Bytes join(const Vector<T>& parts) const {
        Bytes rval;

        for ( size_t i = 0; i < parts.size(); ++i ) {
            if ( i > 0 )
                rval += *this;

            rval += Bytes(hilti::rt::to_string_for_print(parts[i]));
        }

        return rval;
    }

    /**
     * Interprets the data as an ASCII representation of a signed integer and
     * extracts that.
     *
     * @param base base to use for conversion
     * @return converted integer value
     */
    integer::safe<int64_t> toInt(uint64_t base = 10) const;

    /**
     * Interprets the data as an ASCII representation of an unsigned integer
     * and extracts that.
     *
     * @param base base to use for conversion
     * @return converted integer value
     */
    integer::safe<uint64_t> toUInt(uint64_t base = 10) const;

    /**
     * Interprets the data as an binary representation of a signed integer
     * and extracts that.
     *
     * @param byte_order byte order that the integer is encoded in
     * @return converted integer value
     */
    integer::safe<int64_t> toInt(hilti::rt::ByteOrder byte_order) const;

    /**
     * Interprets the data as an binary representation of an unsigned
     * integer and extracts that.
     *
     * @param byte_order byte order that the integer is encoded in
     * @return converted integer value
     */
    integer::safe<uint64_t> toUInt(hilti::rt::ByteOrder byte_order) const;

    /**
     * Interprets the data as an ASCII representation of a floating point value
     * and extracts that. The data must be in a format that `strtod` can handle.
     *
     * @return converted real value
     */
    double toReal() const;

    /**
     * Interprets the data as an ASCII representation of a integer value
     * representing seconds since the UNIX epoch, and extracts that.
     *
     * @param base base to use for conversion
     * @return converted time value
     */
    Time toTime(uint64_t base = 10) const {
        auto ns = ! isEmpty() ? toUInt(base) * integer::safe<uint64_t>(1'000'000'000) : integer::safe<uint64_t>(0);
        return Time(ns, Time::NanosecondTag());
    }

    /**
     * Interprets the data as an binary representation of a integer value
     * representing seconds since the UNIX epoch, and extracts that.
     *
     * @param base base to use for conversion
     * @return converted time value
     */
    Time toTime(hilti::rt::ByteOrder byte_order) const {
        return Time(toUInt(byte_order) * integer::safe<uint64_t>(1'000'000'000), Time::NanosecondTag());
    }

    /**
     * Matches the data against a regular expression.
     *
     * @param re compiled regular expression
     * @param group capture group to return
     * @return the matching group, or unset if no match
     */
    Result<Bytes> match(const RegExp& re, unsigned int group = 0) const;

    // Add some operators over `Base`.
    friend bool operator==(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) == static_cast<const Bytes::Base&>(b);
    }

    friend bool operator!=(const Bytes& a, const Bytes& b) { return ! (a == b); }


    friend bool operator<(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) < static_cast<const Bytes::Base&>(b);
    }

    friend bool operator<=(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) <= static_cast<const Bytes::Base&>(b);
    }

    friend bool operator>(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) > static_cast<const Bytes::Base&>(b);
    }

    friend bool operator>=(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) >= static_cast<const Bytes::Base&>(b);
    }

    friend Bytes operator+(const Bytes& a, const Bytes& b) {
        return static_cast<const Bytes::Base&>(a) + static_cast<const Bytes::Base&>(b);
    }

private:
    friend bytes::SafeIterator;

    void _invalidateIterators() { _control.Reset(); }

    control::Block<Base, InvalidIterator> _control{this};
};

inline std::ostream& operator<<(std::ostream& out, const Bytes& x) {
    out << escapeBytes(x.str(), render_style::Bytes::NoEscapeBackslash);
    return out;
}

namespace bytes::inline literals {
inline Bytes operator""_b(const char* str, size_t size) { return Bytes(Bytes::Base(str, size)); }
} // namespace bytes::inline literals

template<>
inline std::string detail::to_string_for_print<Bytes>(const Bytes& x) {
    return escapeBytes(x.str(), render_style::Bytes::NoEscapeBackslash);
}

namespace detail::adl {
std::string to_string(const Bytes& x, adl::tag /*unused*/);
std::string to_string(const bytes::Side& x, adl::tag /*unused*/);
} // namespace detail::adl

} // namespace hilti::rt

// Disable JSON-ification of `Bytes`.
//
// As of nlohmann-json-0e694b4060ed55df980eaaebc2398b0ff24530d4 the JSON library misdetects the serialization for
// `Bytes` on some platforms. We see this on platforms not providing a C++17-compliant (e.g., in Cirrus' `no-toolchain`
// task which uses gcc-9.3.0) where code in JSON wants to check whether `Bytes` can be converted to a
// `std::filesystem::path`, but then runs into compiler issues.
namespace nlohmann {
template<>
struct adl_serializer<hilti::rt::Bytes> {};
} // namespace nlohmann
