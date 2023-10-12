// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cinttypes>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <hilti/rt/any.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/intrusive-ptr.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/result.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

class Stream;

namespace stream {
class View;
class SafeConstIterator;

namespace detail {
class UnsafeConstIterator;
}
} // namespace stream

namespace detail::adl {
std::string to_string(const Stream& x, adl::tag /*unused*/);
std::string to_string(const stream::View& x, adl::tag /*unused*/);
std::string to_string(const stream::SafeConstIterator& x, adl::tag /*unused*/);
std::string to_string(const stream::detail::UnsafeConstIterator& x, adl::tag /*unused*/);
} // namespace detail::adl

namespace stream {
/** A single element inside a stream instance. */
using Byte = uint8_t;

/** Offset within a stream instance. */
using Offset = integer::safe<uint64_t>;

/** Size of a stream instance in number of elements stores. */
using Size = integer::safe<uint64_t>;

/** Direction of a search. */
enum class Direction : int64_t { Forward, Backward };

namespace detail {

class Chain;
using ChainPtr = IntrusivePtr<Chain>;
using ConstChainPtr = IntrusivePtr<const Chain>;
class UnsafeConstIterator;

// Represents a gap of length `size`.
struct Gap {
    size_t size;
};

/**
 * Represents one block of continuous data inside a stream instance. A
 * stream's *Chain* links multiple of these chunks to represent all of its
 * content.
 *
 * A chunk internally employs small-buffer optimization for very small
 * amounts of data, storing it directly inside the instance instead of using
 * heap-allocated memory.
 *
 * All public methods of Chunk are constant. Modifications can be done only
 * be through the owning Chain (so that we can track changes there).
 */
class Chunk {
public:
    static const int SmallBufferSize = 32;
    using Array = std::pair<Size, std::array<Byte, SmallBufferSize>>;
    using Vector = std::vector<Byte>;

    Chunk(const Offset& o, std::array<Byte, SmallBufferSize> d, const Size& n)
        : _offset(o), _data(std::make_pair(n, d)) {}
    Chunk(const Offset& o, Vector&& d) : _offset(o), _data(std::move(d)) {}
    Chunk(const Offset& o, const View& d);
    Chunk(const Offset& o, const std::string& s);

    template<int N>
    Chunk(Offset o, std::array<Byte, N> d) : Chunk(_fromArray(o, std::move(d))) {}
    Chunk(const Offset& o, const char* d, const Size& n) : Chunk(_fromArray(o, d, n)) {}

    // Constructs a gap chunk which signifies empty data.
    Chunk(const Offset& o, size_t len) : _offset(o), _data(Gap{len}) {}

    Chunk(const Chunk& other) : _offset(other._offset), _data(other._data) {}
    Chunk(Chunk&& other) noexcept
        : _offset(other._offset), _data(std::move(other._data)), _next(std::move(other._next)) {}

    Chunk& operator=(const Chunk& other) = delete;

    Chunk& operator=(Chunk&& other) noexcept {
        _offset = other._offset;
        _data = std::move(other._data);
        _next = std::move(other._next);
        _chain = other._chain;
        return *this;
    }

    ~Chunk();

    Offset offset() const { return _offset; }
    Offset endOffset() const { return _offset + size(); }
    bool isGap() const { return std::holds_alternative<Gap>(_data); }
    bool inRange(const Offset& offset) const { return offset >= _offset && offset < endOffset(); }

    const Byte* data() const {
        if ( auto a = std::get_if<Array>(&_data) )
            return a->second.data();
        else if ( auto a = std::get_if<Vector>(&_data) ) {
            return a->data();
        }
        else if ( std::holds_alternative<Gap>(_data) )
            throw MissingData("data is missing");

        hilti::rt::cannot_be_reached();
    }

    const Byte* data(const Offset& offset) const {
        assert(inRange(offset));
        return data() + (offset - _offset).Ref();
    }

    const Byte* endData() const {
        if ( auto a = std::get_if<Array>(&_data) )
            return a->second.data() + a->first.Ref();
        else if ( auto a = std::get_if<Vector>(&_data) ) {
            return a->data() + a->size();
        }
        else if ( std::holds_alternative<Gap>(_data) )
            throw MissingData("data is missing");

        hilti::rt::cannot_be_reached();
    }

    Size size() const {
        if ( auto a = std::get_if<Array>(&_data) )
            return a->first;
        else if ( auto a = std::get_if<Vector>(&_data) )
            return a->size();
        else if ( auto a = std::get_if<Gap>(&_data) )
            return a->size;

        hilti::rt::cannot_be_reached();
    }

    bool isLast() const { return ! _next; }
    const Chunk* next() const { return _next.get(); }

    auto last() const {
        const Chunk* i = this;
        while ( i && i->_next )
            i = i->_next.get();
        return i;
    }

    auto last() {
        Chunk* i = this;
        while ( i && i->_next )
            i = i->_next.get();
        return i;
    }

    void debugPrint(std::ostream& out) const;

protected:
    // All mutating functions are protected and are expected to be called
    // only from chain so that it can track any changes.
    friend class Chain;

    // Update offset for current chunk and all others linked from it.
    void setOffset(Offset o) {
        auto c = this;
        while ( c ) {
            c->_offset = o;
            o += c->size();
            c = c->next();
        }
    }

    // Set chain for current chunk and all others linked from it.
    void setChain(const Chain* chain) {
        auto x = this;
        while ( x ) {
            x->_chain = chain;
            x = x->_next.get();
        }
    }

    Chunk* next() { return _next.get(); }

    // Link in chunk as successor of current one. Updates offset/chain for
    // the appended chunk and all its successors.
    void setNext(std::unique_ptr<Chunk> next) {
        assert(_chain);

        Offset offset = endOffset();
        _next = std::move(next);

        auto c = _next.get();
        while ( c ) {
            c->_offset = offset;
            c->_chain = _chain;
            offset += c->size();
            c = c->_next.get();
        }
    }

    void clearNext() { _next = nullptr; }

private:
    inline Chunk _fromArray(const Offset& o, const char* d, const Size& n) {
        auto ud = reinterpret_cast<const Byte*>(d);

        if ( n <= Chunk::SmallBufferSize ) {
            std::array<Byte, Chunk::SmallBufferSize> x{};
            std::copy(ud, ud + n.Ref(), x.data());
            return Chunk(o, x, n);
        }

        return Chunk(o, Chunk::Vector(ud, ud + n.Ref()));
    }

    Offset _offset = 0;                     // global offset of 1st byte
    std::variant<Array, Vector, Gap> _data; // content of this chunk
    const Chain* _chain = nullptr; // chain this chunk is part of, or null if not linked to a chain yet (non-owning;
                                   // will stay valid at least as long as the current chunk does)
    std::unique_ptr<Chunk> _next = nullptr; // next chunk in chain, or null if last
};

/**
 * Main data structure for the content of a stream object. A chain is
 * heap-allocated by the stream and retains ownership of the linked chunks. A
 * Chain may survive its stream in the case that iterators to any of its
 * chunks are still around.
 */
class Chain : public intrusive_ptr::ManagedObject {
public:
    using SafeConstIterator = stream::SafeConstIterator;
    using UnsafeConstIterator = stream::detail::UnsafeConstIterator;
    using Size = stream::Size;

    Chain() {}

    /** Moves a chunk and all its successors into a new chain. */
    Chain(std::unique_ptr<Chunk> head) : _head(std::move(head)), _tail(_head->last()) { _head->setChain(this); }

    Chain(Chain&& other) = delete;
    Chain(const Chain& other) = delete;
    Chain& operator=(const Chain& other) = delete;
    Chain& operator=(const Chain&& other) = delete;

    const Chunk* head() const { return _head.get(); }
    const Chunk* tail() const { return _tail; }
    Size size() const { return (endOffset() - offset()).Ref(); }
    bool isFrozen() const { return _state == State::Frozen; }
    bool isValid() const { return _state != State::Invalid; }
    bool inRange(const Offset& o) const { return o >= offset() && o < endOffset(); }

    Offset offset() const { return _head_offset; }
    Offset endOffset() const { return _tail ? _tail->endOffset() : _head_offset; }

    // Finds the chunk containing *offset*. Returns null if not found.
    // *hint_prev* may point to a chunk chained in before the target chunk,
    // allowing that to be found more quickly. If given, *hint_prev* must be
    // pointing to a current chunk of the chain, but it's ok if it's
    // non-helpful for finding the target (i.e., pointing to a later chunk).
    const Chunk* findChunk(const Offset& offset, const Chunk* hint_prev = nullptr) const;
    Chunk* findChunk(const Offset& offset, Chunk* hint_prev = nullptr);

    // Returns a pointer to the byte at a given offset. Returns null if
    // offset is out of range. See find() for semantics of *hint_prev*.
    const Byte* data(const Offset& offset, Chunk* hint_prev = nullptr) const;

    SafeConstIterator begin() const;
    SafeConstIterator end() const;
    SafeConstIterator at(const Offset& offset) const;
    UnsafeConstIterator unsafeBegin() const;
    UnsafeConstIterator unsafeEnd() const;

    // Returns a newly allocated chain with the same content.
    ChainPtr deepCopy() const;

    /** Appends a new chunk to the end. */
    void append(std::unique_ptr<Chunk> chunk);
    void append(Chain&& other);

    void trim(const Offset& offset);
    void trim(const SafeConstIterator& i);
    void trim(const UnsafeConstIterator& i);

    // Turns the chain into invalidated state, whill releases all chunks and
    // will let attempts to dereference any still existing iterators fail.
    void invalidate() {
        _state = State::Invalid;
        _head.reset();
        _head_offset = 0;
        _tail = nullptr;
    }

    // Turns the chain into a freshly initialized state.
    void reset() {
        _state = State::Mutable;
        _head.reset();
        _head_offset = 0;
        _tail = nullptr;
    }

    void freeze() {
        if ( isValid() )
            _state = State::Frozen;
    }
    void unfreeze() {
        if ( isValid() )
            _state = State::Mutable;
    }

    // Returns the number of dynamic chunks allocated.
    int numberOfChunks() const;

private:
    void _ensureValid() const {
        if ( ! isValid() )
            throw InvalidIterator("stream object no longer available");
    }

    void _ensureMutable() const {
        if ( isFrozen() )
            throw Frozen("stream object can no longer be modified");
    }

    enum class State {
        Mutable, // content can be expanded an trimmed
        Frozen,  // content cannot be changed
        Invalid, // parent stream object has been destroyed, all content is invalid
    };

    // Current state of chain
    State _state = State::Mutable;

    // First chunk, or null if chain is empty.
    std::unique_ptr<Chunk> _head = nullptr;

    // Offset of the beginning of chain. If head is set, this offset will
    // match that of head. If head is not set, it'll contain the most recent
    // end offset of the main (that's zero initially, but may be non-zero
    // after trimming off all chunks).
    Offset _head_offset = 0;

    // Always pointing to last chunk reachable from *head*, or null if chain
    // is empty; non-owning
    Chunk* _tail = nullptr;
};

} // namespace detail

/**
 * SafeConstIterator for traversing the content of a stream instance.
 *
 * Unlike the STL-style iterators, this iterator protects against the stream
 * instance being no longer available by throwing an `InvalidIterator`
 * exception if it's still accessed. It will also catch attempts to
 * dereference iterators that remain outside of the current valid range of
 * the underlying stream. However, operations that only query/manipulate
 * offsets will succeed even for out-of-range positions. That includes
 * advancing an iterator beyond the end of a stream, which is well-defined:
 * if the stream gets expanded later, the iterator will refer to any data
 * ending up at the iterator's position now.
 */
class SafeConstIterator {
public:
    using Byte = stream::Byte;
    using Chain = stream::detail::Chain;
    using ConstChainPtr = stream::detail::ConstChainPtr;
    using Chunk = stream::detail::Chunk;
    using Offset = stream::Offset;
    using Size = stream::Size;
    using UnsafeConstIterator = stream::detail::UnsafeConstIterator;

    /** Constructor. */
    SafeConstIterator() = default;

    /** Constructor. */
    explicit SafeConstIterator(const UnsafeConstIterator& i);

    /** Returns the offset inside the stream that the iterator represents. */
    Offset offset() const { return _offset; }

    /** Returns true if the stream instance that the iterator is bound to has been frozen.  */
    bool isFrozen() const { return ! _chain || _chain->isFrozen(); }

    /** Advances the iterator by one byte. */
    auto& operator++() {
        _increment(1);
        return *this;
    }

    /** Advances the iterator by one byte. */
    auto operator++(int) {
        auto x = *this;
        _increment(1);
        return x;
    }

    /** Advances the iterator by a given number of stream. */
    auto& operator+=(const integer::safe<uint64_t>& i) {
        _increment(i);
        return *this;
    }

    /** Moves back the iterator by one byte. */
    auto& operator--() {
        _decrement(1);
        return *this;
    }

    /** Moves back the iterator by one byte. */
    auto operator--(int) {
        auto x = *this;
        _decrement(1);
        return x;
    }

    /** Moves back the iterator by a given number of stream. */
    auto& operator-=(const integer::safe<uint64_t>& i) {
        _decrement(i);
        return *this;
    }

    /** Returns the character at the iterator's position. */
    auto operator*() const { return _dereference(); }

    /** Return a new iterator advanced by a given number of bytes. */
    auto operator+(const integer::safe<uint64_t>& i) const {
        auto x = *this;
        x._increment(i);
        return x;
    }

    /** Returns a new iterator moved back by a given number of bytes. */
    auto operator-(const integer::safe<uint64_t>& i) const {
        auto x = *this;
        x._decrement(i);
        return x;
    }

    /**
     * Return the size of the range defined by the two iterators. The result
     * will be negative if the instance's location comes before the
     * argument's location.
     */
    integer::safe<int64_t> operator-(const SafeConstIterator& other) const {
        _ensureSameChain(other);
        return static_cast<int64_t>(_offset) - static_cast<int64_t>(other._offset);
    }

    /**
     * Returns true if another iterator bound to the same stream instance
     * refers to the same location. The result is undefined if the iterators
     * aren't referring to the same stream instance.
     */
    bool operator==(const SafeConstIterator& other) const {
        _ensureSameChain(other);
        return (_offset == other._offset) || (isEnd() && other.isEnd());
    }

    /**
     * Returns true if another iterator bound to the same stream instance does
     * not refer to the same location. The result is undefined if the
     * iterators aren't referring to the same stream instance.
     */
    bool operator!=(const SafeConstIterator& other) const {
        _ensureSameChain(other);
        return ! (*this == other);
    }

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator<(const SafeConstIterator& other) const {
        _ensureSameChain(other);
        return offset() < other.offset();
    }

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator<=(const SafeConstIterator& other) const {
        _ensureSameChain(other);
        return offset() <= other.offset();
    }

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator>(const SafeConstIterator& other) const {
        _ensureSameChain(other);
        return offset() > other.offset();
    }

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator>=(const SafeConstIterator& other) const {
        _ensureSameChain(other);
        return offset() >= other.offset();
    }

    /** Returns true if the iterator is bound to a stream instance, even if expired. */
    explicit operator bool() const { return ! isUnset(); }

    std::ostream& operator<<(std::ostream& out) const {
        out << to_string(*this);
        return out;
    }

    /** Returns true if the iterator remains unbound. */
    bool isUnset() const { return ! _chain; }

    /**
     * Returns true if the iterator was once valid but the underlying bytes
     * instance has by now expired.
     */
    bool isExpired() const {
        if ( ! _chain )
            return false;

        return ! _chain->isValid();
    }

    /**
     * Returns true if the iterator is bound to a stream object and that's
     * not expired yet.
     */
    bool isValid() const { return ! isUnset() && ! isExpired(); }

    /**
     * Returns true if the iterator is at or beyond the current end of the
     * underlying stream instance. Also generally returns true for an unbound
     * iterator.
     */
    bool isEnd() const {
        if ( ! _chain )
            return true;

        _ensureValidChain();
        return _offset >= _chain->endOffset();
    }

    /**
     * Prints out a debug rendering to the iterator's internal
     * representation.
     */
    void debugPrint(std::ostream& out) const;

protected:
    friend class hilti::rt::stream::View;
    friend class hilti::rt::stream::detail::Chain;
    friend class hilti::rt::stream::detail::UnsafeConstIterator;

    // Returns the chunk only if it's a valid pointer, other null. See
    // comment on `_chunk` validity below.
    const Chunk* chunk() const { return _chain && _chain->isValid() && _chain->inRange(_offset) ? _chunk : nullptr; }
    const Chain* chain() const { return _chain.get(); }

private:
    SafeConstIterator(ConstChainPtr chain, const Offset& offset, const Chunk* chunk)
        : _chain(std::move(chain)), _offset(offset), _chunk(chunk) {
        assert(! isUnset());
    }

    void _ensureValidChain() const {
        // This must have been checked at this point already.
        assert(_chain);

        if ( ! _chain->isValid() )
            throw InvalidIterator("stream object no longer available");
    }

    void _ensureSameChain(const SafeConstIterator& other) const {
        if ( ! (_chain && other._chain) )
            // One is the default constructed end iterator; that's ok.
            return;

        if ( ! other.isValid() )
            throw InvalidIterator("stream object no longer available");

        if ( _chain != other._chain )
            throw InvalidIterator("incompatible iterators");
    }

    void _increment(const integer::safe<uint64_t>& n) {
        if ( ! _chain )
            throw InvalidIterator("unbound stream iterator");

        if ( ! n )
            return;

        _offset += n;

        if ( ! (_chain && _chain->isValid()) )
            return; // will be caught when dereferenced

        _chunk = _chain->findChunk(_offset, chunk());
        // chunk will be null if we're pointing beyond the end.
    }

    void _decrement(const integer::safe<uint64_t>& n) {
        if ( ! _chain )
            throw InvalidIterator("unbound stream iterator");

        if ( n > _offset )
            throw InvalidIterator("attempt to move before beginning of stream");

        if ( ! n )
            return;

        _offset -= n;

        if ( _chunk && _offset > _chunk->offset() )
            return; // fast-path, chunk still valid

        if ( ! (_chain && _chain->isValid()) )
            return; // will be caught when dereferenced

        _chunk = _chain->findChunk(_offset, _chunk);
        // chunk will be null if we're pointing beyond the beginning.
    }

    Byte _dereference() const {
        if ( ! _chain )
            throw InvalidIterator("unbound stream iterator");

        _ensureValidChain();

        if ( ! _chain->inRange(_offset) )
            throw InvalidIterator("stream iterator outside of valid range");

        auto c = _chain->findChunk(_offset, chunk());
        assert(c);

        if ( c->isGap() )
            throw MissingData("data is missing");

        return *c->data(_offset);
    }

    // Parent chain if bound, or null if not. The parent will stay around for
    // at least as long as this iterator.
    ConstChainPtr _chain = nullptr;

    // Global offset inside parent chain. This can be pointing to anywhere
    // inside the stream's sequence space, including potentially being
    // outside of the chain's valid range. It may always be accessed, even if
    // the iterator is unbound, or the chain not valid anymore; it will then
    // generally reflect the most recent value, which may or may not
    // semantically make sense.
    Offset _offset = 0;

    // A chunk from which *_offset* is reachable (i.e., the chunk either
    // contains the offset, or we can get to the right chunk by following its
    // successors). The chunk is null if our current offset is outside of the
    // chains valid range.
    //
    // This chunk pointer is only valid for access if (1) *_chain* is set and
    // valid; and (2) _offset is inside the chain's valid range. It will then
    // point to a chunk from which _offset is *reachable*. (If these two are
    // not satisfied, the chunk may be pointing into freed memory!)
    const Chunk* _chunk = nullptr;
};

inline std::ostream& operator<<(std::ostream& out, const SafeConstIterator& x) {
    out << to_string(x);
    return out;
}

/**
 * Standard, unsafe iterator for internal usage. Unlike *SafeConstIterator*,
 * this iterator version is not safe against the underlying stream instances
 * disappearing or even changing; it will not catch that and likely causes
 * crashes on access It also does not perform any bounds-checking. When using
 * this, one hence needs to ensure that the stream instance will remain valid
 * & unchanged for long as the iterator remains alive. In return, this
 * iterator is more efficient than the `SafeConstIterator`.
 */

namespace detail {

class UnsafeConstIterator {
public:
    using Byte = stream::Byte;
    using Chain = stream::detail::Chain;
    using ConstChainPtr = stream::detail::ConstChainPtr;
    using Chunk = stream::detail::Chunk;
    using Offset = stream::Offset;
    using Size = stream::Size;

    /** Constructor. */
    UnsafeConstIterator() = default;

    /** Constructor. */
    explicit UnsafeConstIterator(const SafeConstIterator& i);

    /** Returns the offset inside the stream that the iterator represents. */
    Offset offset() const { return _offset; }

    /** Returns true if the stream instance that the iterator is bound to has been frozen.  */
    bool isFrozen() const { return ! _chain || _chain->isFrozen(); }

    /** Advances the iterator by one byte. */
    auto& operator++() {
        _increment(1);
        return *this;
    }

    /** Advances the iterator by one byte. */
    auto operator++(int) {
        auto x = *this;
        _increment(1);
        return x;
    }

    /** Moves back the iterator by one byte. */
    auto& operator--() {
        _decrement(1);
        return *this;
    }

    /** Moves back the iterator by one byte. */
    auto operator--(int) {
        auto x = *this;
        _decrement(1);
        return x;
    }

    /** Moves back the iterator by a given number of stream. */
    auto& operator-=(const integer::safe<uint64_t>& i) {
        _decrement(i);
        return *this;
    }

    /** Returns the character at the iterator's position. */
    auto operator*() const { return _dereference(); }

    /** Return a new iterator advanced by a given number of bytes. */
    auto operator+(const integer::safe<uint64_t>& i) const {
        auto x = *this;
        x._increment(i);
        return x;
    }

    /** Return a new iterator moved back by a given number of bytes. */
    auto operator-(const integer::safe<uint64_t>& i) const {
        auto x = *this;
        x._decrement(i);
        return x;
    }

    /**
     * Return the size of the range defined by the two iterators. The result
     * will be negative if the instance's location comes before the
     * argument's location.
     */
    integer::safe<int64_t> operator-(const UnsafeConstIterator& other) const {
        return static_cast<int64_t>(_offset) - static_cast<int64_t>(other._offset);
    }

    /**
     * Returns true if another iterator bound to the same stream instance
     * refers to the same location. The result is undefined if the iterators
     * aren't referring to the same stream instance.
     */
    bool operator==(const UnsafeConstIterator& other) const {
        return (_offset == other._offset) || (isEnd() && other.isEnd());
    }

    /**
     * Returns true if another iterator bound to the same stream instance does
     * not refer to the same location. The result is undefined if the
     * iterators aren't referring to the same stream instance.
     */
    bool operator!=(const UnsafeConstIterator& other) const { return ! (*this == other); }

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator<(const UnsafeConstIterator& other) const { return offset() < other.offset(); }

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator<=(const UnsafeConstIterator& other) const { return offset() <= other.offset(); }

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator>(const UnsafeConstIterator& other) const { return offset() > other.offset(); }

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator>=(const UnsafeConstIterator& other) const { return offset() >= other.offset(); }

    /** Returns true if the iterator is bound to a stream instance, even if expired. */
    explicit operator bool() const { return ! isUnset(); }

    std::ostream& operator<<(std::ostream& out) const {
        out << to_string(*this);
        return out;
    }

    /** Returns true if the iterator remains unbound. */
    bool isUnset() const { return ! _chain; }

    /**
     * Returns true if the iterator was once valid but the underlying bytes
     * instance has by now expired.
     */
    bool isExpired() const {
        if ( ! _chain )
            return false;

        return ! _chain->isValid();
    }

    /**
     * Returns true if the iterator is bound to a stream object and that's
     * not expired yet.
     */
    bool isValid() const { return ! isUnset() && ! isExpired(); }

    /** Returns true if the iterator is at or beyond the current end of the underlying stream instance. */
    bool isEnd() const {
        if ( ! _chain )
            return true;

        return _offset >= _chain->endOffset();
    }

    /**
     * Prints out a debug rendering to the iterator's internal
     * representation.
     */
    void debugPrint(std::ostream& out) const;

protected:
    friend class hilti::rt::stream::View;
    friend class hilti::rt::stream::detail::Chain;
    friend class hilti::rt::stream::SafeConstIterator;

    const Chunk* chunk() const { return _chunk; }
    const Chain* chain() const { return _chain; }

private:
    UnsafeConstIterator(const ConstChainPtr& chain, const Offset& offset, const Chunk* chunk)
        : _chain(chain.get()), _offset(offset), _chunk(chunk) {
        assert(! isUnset());
    }

    UnsafeConstIterator(const Chain* chain, const Offset& offset, const Chunk* chunk)
        : _chain(chain), _offset(offset), _chunk(chunk) {
        assert(! isUnset());
    }

    void _increment(const integer::safe<uint64_t>& n) {
        _offset += n;

        if ( _chunk && _offset < _chunk->endOffset() )
            return; // fast-path, chunk still valid

        _chunk = _chain->findChunk(_offset, _chunk);
    }

    void _decrement(const integer::safe<uint64_t>& n) {
        _offset -= n;

        if ( _chunk && _offset > _chunk->offset() )
            return; // fast-path, chunk still valid

        _chunk = _chain->findChunk(_offset, _chunk);
    }

    Byte _dereference() const {
        // TODO(bbannier): Ideally we would `assert(_chunk)` here so clang-tidy
        // knows that `_chunk` is always not null. Unfortunately it looks like
        // that fails to it pruning that CFG edge so we have to return instead
        // here. This should be inconsequential to users as this function must
        // not be called if the data is invalid.
        if ( ! _chunk )
            internalError("dereference of invalid iterator");

        auto* byte = _chunk->data(_offset);

        if ( ! byte )
            throw MissingData("data is missing");

        return *byte;
    }

    // Parent chain if bound, or null if not. This is a raw, non-owning
    // pointer that assumes the parent chain will stick around as long as
    // needed.
    const Chain* _chain = nullptr;

    // Global offset inside parent chain. This can be pointing to anywhere
    // inside the stream's sequence space, including potentially being
    // outside of the chain's valid range.
    Offset _offset = 0;

    // The chunk containing the current offset, or null if offset is out of
    // bounds. This a raw, non-owning pointer that assumes the chunk will
    // stick around as long as needed.
    const Chunk* _chunk = nullptr;
};

inline UnsafeConstIterator::UnsafeConstIterator(const SafeConstIterator& i)
    : _chain(i.chain()), _offset(i.offset()), _chunk(i.chain() ? i.chain()->findChunk(_offset, i.chunk()) : nullptr) {}

inline std::ostream& operator<<(std::ostream& out, const UnsafeConstIterator& x) {
    out << to_string(x);
    return out;
}

inline SafeConstIterator Chain::begin() const {
    _ensureValid();
    return {ConstChainPtr(intrusive_ptr::NewRef(), this), offset(), _head.get()};
}

inline SafeConstIterator Chain::end() const {
    _ensureValid();
    return {ConstChainPtr(intrusive_ptr::NewRef(), this), endOffset(), _tail};
}

inline SafeConstIterator Chain::at(const Offset& offset) const {
    return {ConstChainPtr(intrusive_ptr::NewRef(), this), offset, findChunk(offset)};
}

inline UnsafeConstIterator Chain::unsafeBegin() const {
    _ensureValid();
    return {ConstChainPtr(intrusive_ptr::NewRef(), this), offset(), _head.get()};
}
inline UnsafeConstIterator Chain::unsafeEnd() const {
    _ensureValid();
    return {ConstChainPtr(intrusive_ptr::NewRef(), this), endOffset(), _tail};
}

inline void Chain::trim(const SafeConstIterator& i) {
    if ( ! i.chain() ) {
        // Unbound end operator, trim all content off.
        trim(endOffset());
        return;
    }

    if ( i.chain() != this )
        throw InvalidIterator("incompatible iterator");

    if ( ! i.isValid() )
        throw InvalidIterator("stream object no longer available");

    trim(i.offset());
}

inline void Chain::trim(const UnsafeConstIterator& i) { trim(i.offset()); }

inline const Chunk* Chain::findChunk(const Offset& offset, const Chunk* hint_prev) const {
    _ensureValid();

    const Chunk* c = _head.get();

    // A very common way this function gets called without `hint_prev` is
    // `Stream::unsafeEnd` via `Chain::unsafeEnd` in construction of an
    // `UnsafeConstIterator` from a `SafeConstIterator`; in this case the chunk
    // for `end()` will be `nullptr`. Optimize for that case by assuming we
    // always want a chunk near the end if no hint is given.
    if ( ! hint_prev )
        hint_prev = _tail;

    if ( hint_prev && hint_prev->offset() <= offset )
        c = hint_prev;

    while ( c && ! c->inRange(offset) )
        c = c->next();

    if ( c && ! c->inRange(offset) )
        return nullptr;

    return c;
}

inline Chunk* Chain::findChunk(const Offset& offset, Chunk* hint_prev) {
    _ensureValid();

    Chunk* c = _head.get();

    // See comment above.
    if ( ! hint_prev )
        hint_prev = _tail;

    if ( hint_prev && hint_prev->offset() <= offset )
        c = hint_prev;

    while ( c && ! c->inRange(offset) )
        c = c->next();

    if ( _tail && offset > _tail->endOffset() )
        return _tail;

    return c;
}

inline const Byte* Chain::data(const Offset& offset, Chunk* hint_prev) const {
    auto c = findChunk(offset, hint_prev);
    if ( ! c )
        throw InvalidIterator("stream iterator outside of valid range");

    return c->data(offset);
}


} // namespace detail

inline SafeConstIterator::SafeConstIterator(const UnsafeConstIterator& i)
    : _chain(detail::ConstChainPtr(intrusive_ptr::NewRef(), i._chain)), _offset(i._offset), _chunk(i._chunk) {}

/**
 * A subrange of a stream instance. The view is maintained through two safe
 * iterators; no data is copied. That makes the view cheap to create and pass
 * around. Because of the use of safe containers, it'll also be caught if the
 * underlying stream instances goes away, or if accesses outside of
 * currently valid range occur.
 */
class View final {
public:
    using Byte = stream::Byte;
    using Chain = stream::detail::Chain;
    using ChainPtr = stream::detail::ChainPtr;
    using Chunk = stream::detail::Chunk;
    using Offset = stream::Offset;
    using Size = stream::Size;
    using UnsafeConstIterator = stream::detail::UnsafeConstIterator;

    /** Constructor. */
    View() = default;

    /** Destructor. */
    ~View() = default;

    /** Constructor for static view bracketed through two iterators. */
    explicit View(SafeConstIterator begin, SafeConstIterator end) : _begin(std::move(begin)), _end(std::move(end)) {
        _ensureValid();

        if ( ! _end->_chain )
            _end = _begin.chain()->end();
        else
            _ensureSameChain(*_end);
    }

    /**
     * Constructor for an expanding view that will always reflect a range up
     * to the current end of the underlying stream object, including when that
     * expands.
     */
    explicit View(SafeConstIterator begin) : _begin(std::move(begin)) {}

    /**
     * Returns the offset of the view's starting location within the associated
     * stream instance.
     */
    Offset offset() const { return _begin.offset(); }

    /**
     * Returns the offset of the view's end location within the associated
     * stream instance. For an open-ended view, returns an unset value.
     */
    std::optional<Offset> endOffset() const {
        if ( _end )
            return _end->offset();
        else
            return std::nullopt;
    }

    /**
     * Returns the number of actual bytes available inside the view. If the
     * view's end position is beyond the current end offset of the underlying
     * stream, those missing bytes are not counted.
     */
    Size size() const;

    /** Returns true if the view's size is zero. */
    bool isEmpty() const { return size() == 0; }

    /** Returns true if the instance is currently frozen. */
    bool isFrozen() const { return _begin.isFrozen(); }

    /**
     * Returns true if the view was constructed without a fixed end offset,
     * meaning it will expand as more data gets added to the underlying
     * stream.
     */
    bool isOpenEnded() const { return ! _end.has_value(); }

    /**
     * Returns the position of the first occurrence of a byte inside the
     * view. Will return *end()* if not found.
     *
     * @param b byte to search
     */
    SafeConstIterator find(Byte b) const {
        _ensureValid();
        return SafeConstIterator(find(b, UnsafeConstIterator()));
    }

    /**
     * Returns the position of the first occurrence of a byte inside the
     * view. Will return *end()* if not found.
     *
     * @param b byte to search
     * @param n starting point, which must be inside the view
     */
    SafeConstIterator find(Byte b, const SafeConstIterator& n) const {
        _ensureValid();
        _ensureSameChain(n);
        return SafeConstIterator(find(b, UnsafeConstIterator(n)));
    }

    /**
     * Returns the position of the first occurrence of a byte inside the
     * view. Will return *unsafeEnd()* if not found.
     *
     * @param b byte to search
     * @param n starting point, which must be inside the view
     */
    UnsafeConstIterator find(Byte b, UnsafeConstIterator n) const;

    /**
     * Searches for the first occurrence of another view's data.
     *
     * @param v data to search for
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st occurrence;
     * if no, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*.
     */
    std::tuple<bool, SafeConstIterator> find(const View& v) const {
        _ensureValid();
        auto x = find(v, UnsafeConstIterator());
        return std::make_tuple(std::get<0>(x), SafeConstIterator(std::get<1>(x)));
    }

    /**
     * Searches for the first occurrence of another view's data.
     *
     * @param v data to search for
     * @param n starting point, which must be inside this view
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st occurrence;
     * if no, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*.
     */
    std::tuple<bool, SafeConstIterator> find(const View& v, const SafeConstIterator& n) const {
        _ensureValid();
        _ensureSameChain(n);
        auto x = find(v, UnsafeConstIterator(n));
        return std::make_tuple(std::get<0>(x), SafeConstIterator(std::get<1>(x)));
    }

    /**
     * Searches for the first occurrence of another view's data.
     *
     * @param v data to search for
     * @param n starting point, which must be inside this view
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st
     * occurrence; if no, the 2nd element points to the first byte so that no
     * earlier position has even a partial match of *v*.
     */
    std::tuple<bool, UnsafeConstIterator> find(const View& v, UnsafeConstIterator n) const;

    /**
     * Searches for the first occurrence of data, either forward or backward.
     *
     * @param v data to search for
     * @param d direction to search: forward searches from the beginning, backward from the end of the view
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st byte;
     * if no, then with forward searching, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*
     */
    std::tuple<bool, SafeConstIterator> find(const Bytes& v, Direction d = Direction::Forward) const {
        _ensureValid();
        auto i = (d == Direction::Forward ? unsafeBegin() : unsafeEnd());
        auto x = find(v, i, d);
        return std::make_tuple(std::get<0>(x), SafeConstIterator(std::get<1>(x)));
    }

    /**
     * Searches for the first occurrence of data, either forward or backward.
     *
     * @param v data to search for
     * @param n starting point, which must be inside this view
     * @param d direction to search from starting point
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st byte;
     * if no, then with forward searching, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*
     */
    std::tuple<bool, SafeConstIterator> find(const Bytes& v, const SafeConstIterator& n,
                                             Direction d = Direction::Forward) const {
        _ensureValid();
        _ensureSameChain(n);
        auto x = find(v, UnsafeConstIterator(n), d);
        return std::make_tuple(std::get<0>(x), SafeConstIterator(std::get<1>(x)));
    }

    /**
     * Searches for the first occurrence of data, either forward or backward.
     *
     * @param v data to search for
     * @param n starting point, which must be inside this view
     * @param d direction to search from starting point
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st byte;
     * if no, then with forward searching, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*
     */
    std::tuple<bool, UnsafeConstIterator> find(const Bytes& v, UnsafeConstIterator n,
                                               Direction d = Direction::Forward) const {
        if ( d == Direction::Forward )
            return _findForward(v, n);
        else
            return _findBackward(v, n);
    }

    /**
     * Advances the view's starting position to a new place.
     *
     * @param i the new position, which must be inside the current view
     * @return the modified view
     */
    View advance(SafeConstIterator i) const {
        _ensureSameChain(i);
        return View(std::move(i), _end);
    }

    /**
     * Advances the view's starting position by a given number of stream.
     *
     * @param i the number of stream to advance.
     */
    View advance(const integer::safe<uint64_t>& i) const { return View(begin() + i, _end); }

    /**
     * Advances the view to the next, none gap offset. This always advances at least by one byte.
     */
    View advanceToNextData() const;

    /**
     * Extracts a subrange of bytes from the view, returned as a new view.
     *
     * @param from iterator pointing to start of subrange
     * @param to iterator pointing to just beyond subrange
     */
    View sub(SafeConstIterator from, SafeConstIterator to) const {
        _ensureSameChain(from);
        _ensureSameChain(to);
        return View(std::move(from), std::move(to));
    }

    /**
     * Extracts subrange of bytes from the beginning of the view, returned as
     * a new view.
     *
     * @param to iterator pointing to just beyond subrange
     */
    View sub(SafeConstIterator to) const {
        _ensureSameChain(to);
        return View(begin(), std::move(to));
    }

    /**
     * Extracts subrange of bytes from the view, returned as a new view.
     *
     * @param from offset of start of subrange, relative to beginning of view
     * @param to offset of one beyond end of subrange, relative to beginning of view
     */
    View sub(const Offset& from, const Offset& to) const { return View(begin() + from, begin() + to); }

    /**
     * Extracts subrange of stream from the beginning of the view, returned as
     * a new view.
     *
     * @param to of one beyond end of subrange, relative to beginning of view
     */
    View sub(const Offset& to) const { return View(begin(), begin() + to); }

    /** Returns an iterator representing an offset inside the view's data */
    SafeConstIterator at(const Offset& offset) const { return begin() + (offset - begin().offset()); }

    /**
     * Returns a new view moves the beginning to a subsequent iterator while
     * not changing the end. In particular, this maintains a view capability
     * to expand to an underlying data instance's growth.
     */
    View trim(const SafeConstIterator& nbegin) const {
        _ensureSameChain(nbegin);

        if ( ! _end )
            return View(nbegin);

        if ( nbegin.offset() > _end->offset() )
            return View(*_end, *_end);

        return View(nbegin, *_end);
    }

    /**
     * Returns a new view that keeps the current start but cuts off the end
     * at a specified offset from that beginning. The returned view will not
     * be able to expand any further.
     */
    View limit(const Offset& incr) const { return View(begin(), begin() + incr); }

    /**
     * Extracts a fixed number of stream bytes from the view.
     *
     * @param dst target array to write stream data into
     * @param n number of stream bytes to extract
     * @return new view that has it's starting position advanced by N
     */
    View extract(Byte* dst, uint64_t n) const {
        _ensureValid();

        // Fast-path for when we're staying inside the initial chunk.
        if ( auto chunk = _begin.chunk(); chunk && chunk->inRange(_begin.offset() + n) ) {
            memcpy(dst, chunk->data(_begin.offset()), n);
            return View(SafeConstIterator(_begin._chain, _begin.offset() + n, chunk), _end);
        }

        if ( n > size() )
            throw WouldBlock("end of stream view");

        auto p = unsafeBegin();
        for ( uint64_t i = 0; i < n; ++i )
            dst[i] = *p++;

        return View(SafeConstIterator(p), _end);
    }

    /**
     * Copies the view into raw memory.
     *
     * @param dst destination to write to, which must have at least `size()`
     * stream available().
     */
    void copyRaw(Byte* dst) const;

    /** Returns a copy of the data the view refers to. */
    Bytes data() const;

    /** Returns a string representation of the data the view refers to. */
    std::string dataForPrint() const;

    /** Returns an unsafe iterator pointing to the beginning of the view. */
    detail::UnsafeConstIterator unsafeBegin() const { return detail::UnsafeConstIterator(_begin); }

    /** Returns an unsafe iterator representing the end of the instance. */
    detail::UnsafeConstIterator unsafeEnd() const { return detail::UnsafeConstIterator(end()); }

    /** Returns an safe iterator pointint to the beginning of the view. */
    const SafeConstIterator& begin() const { return _begin; }

    /** Returns a safe iterator representing the end of the instance. */
    SafeConstIterator end() const {
        assert(_begin.chain());
        return _end ? *_end : _begin.chain()->end();
    }

    /** State for block-wise iteration of a stream instance. */
    struct Block {
        const Byte* start;           /**< Pointer to first byte. */
        uint64_t size;               /**< Number of stream in block. */
        uint64_t offset;             /**< Offset of first byte. */
        bool is_first;               /**< true if first block visited during iteration. */
        bool is_last;                /**< true if last block that will be visited during iteration. */
        const detail::Chunk* _block; /**< Internal use only. */
    };

    /**
     * Initialization method for block-wise iteration over raw data.
     */
    std::optional<Block> firstBlock() const;

    /**
     * Iterates to next block during block-wise iteration over raw data.
     */
    std::optional<Block> nextBlock(std::optional<Block> current) const;

    /**
     * Returns true if the view's data begins with a given, other stream
     * instance.
     */
    bool startsWith(const Bytes& b) const;

    bool operator==(const Bytes& other) const;
    bool operator==(const Stream& other) const;
    bool operator==(const View& other) const;
    bool operator!=(const Bytes& other) const { return ! (*this == other); }
    bool operator!=(const Stream& other) const { return ! (*this == other); }
    bool operator!=(const View& other) const { return ! (*this == other); }

    /**
     * Prints out a debug rendering to the view's internal representation.
     */
    void debugPrint(std::ostream& out) const;

private:
    View(SafeConstIterator begin, std::optional<SafeConstIterator> end)
        : _begin(std::move(begin)), _end(std::move(end)) {
        if ( _end )
            _ensureSameChain(*_end);
    }

    void _ensureSameChain(const SafeConstIterator& other) const {
        if ( _begin.chain() != other.chain() )
            throw InvalidIterator("incompatible iterator");
    }

    void _ensureValid() const {
        //        if ( ! _begin.chain() )
        //            throw InvalidIterator("view has invalid beginning");

        //        if ( ! _begin.isValid() )
        //            throw InvalidIterator("view has invalid beginning");

        if ( _end && ! _end->isValid() )
            throw InvalidIterator("view has invalid end");
    }

    virtual void _force_vtable(); // force creation of consistent vtable for RTTI; not used otherwise

    // Common backend for backward searching.
    std::tuple<bool, UnsafeConstIterator> _findBackward(const Bytes& needle, UnsafeConstIterator i) const;

    // Common backend for forward searching.
    std::tuple<bool, UnsafeConstIterator> _findForward(const Bytes& v, UnsafeConstIterator n) const;

    SafeConstIterator _begin;
    std::optional<SafeConstIterator> _end;
};

inline Size View::size() const {
    // Because our end offset may point beyond what's currently
    // available, we need to take the actual end in account to return
    // the number of actually available bytes.

    if ( ! _begin.chain() )
        return 0;

    auto tail = _begin.chain()->tail();
    if ( ! tail )
        return 0;

    if ( _begin.offset() > tail->endOffset() )
        return 0;

    if ( ! _end || _end->offset() >= tail->endOffset() )
        return tail->endOffset() - _begin.offset();
    else
        return _end->offset() > _begin.offset() ? (_end->offset() - _begin.offset()).Ref() : 0;
}

inline Bytes stream::View::data() const {
    Bytes s;
    s.append(*this);
    return s;
}

inline std::ostream& operator<<(std::ostream& out, const View& x) { return out << hilti::rt::to_string_for_print(x); }
} // namespace stream

/**
 * Container for raw binary data that's going to be processed in streaming
 * mode. The underlying data storage is optimized for cheap *append*
 * operations even with large instances, but does not allow for any
 * modifications to existing data. It also ensures that iterators bound to an
 * instance can reliably detect if the instance gets deleted.
 *
 * Internally, almost all functionality is delegated to a *Chain* instance,
 * which resides on the heap.
 */
class Stream {
private:
    using Byte = stream::Byte;
    using Chain = stream::detail::Chain;
    using ChainPtr = stream::detail::ChainPtr;
    using Chunk = stream::detail::Chunk;
    using Offset = stream::Offset;
    using SafeConstIterator = stream::SafeConstIterator;
    using Size = stream::Size;
    using UnsafeConstIterator = stream::detail::UnsafeConstIterator;
    using View = stream::View;

public:
    /** Constructor. */
    Stream() : _chain(make_intrusive<Chain>()) {}

    /**
     * Creates an instance from a vector of `Bytes`.
     * @param d `vector` to create the stream from
     */
    explicit Stream(std::vector<Byte> d) : Stream(Chunk(0, std::move(d))) {}

    /**
     * Creates an instance from a bytes instance.
     * @param d `Bytes` instance to the create the stream from
     */
    explicit Stream(const Bytes& d);

    /**
     * Creates an instance for C-style ASCII string, not including the final null byte. The data will be copied.
     * @param d null-terminated string to create the stream from
     */
    explicit Stream(const char* d) : Stream(Chunk(0, d, strlen(d))) {}

    /**
     * Creates an instance from an existing memory block. The data
     * will be copied if set, otherwise a gap will be recorded.
     */
    Stream(const char* d, const Size& n);
    /**
     * Creates an instance from an existing stream view.
     * @param d `View` to create the stream from
     */
    Stream(const stream::View& d) : Stream(Chunk(0, d)) {}

    /**
     * Creates an instance from a series of static-sized blocks.
     * @param d a vector of `N`-sized arrays to create the stream from
     */
    template<int N>
    Stream(std::vector<std::array<Byte, N>> d) : Stream(chunkFromArray(0, std::move(d))) {}

    /**
     * Constructs a stream from another stream instance.
     * @param other instance to create this stream from
     */
    Stream(const Stream& other) : _chain(other._chain->deepCopy()) {}

    /**
     * Constructs a stream from another stream instance.
     * @param other instance to create this stream from
     */
    Stream(Stream&& other) noexcept : _chain(std::move(other._chain)) { other._chain = make_intrusive<Chain>(); }

    /**
     * Assigns from another stream instance. This invalidates all existing iterators.
     * @param other the stream instance to assign from
     */
    Stream& operator=(Stream&& other) noexcept {
        if ( &other == this )
            return *this;

        _chain->invalidate();
        _chain = std::move(other._chain);
        other._chain = make_intrusive<Chain>();
        return *this;
    }

    /**
     * Assigns from another stream instance. This invalidates all existing iterators.
     * @param other the stream instance to assign from
     */
    Stream& operator=(const Stream& other) {
        if ( &other == this )
            return *this;

        _chain->invalidate();
        _chain = other._chain->deepCopy();
        return *this;
    }

    /** Destructor. */
    ~Stream() {
        assert(_chain);
        _chain->invalidate();
    }

    /** Returns the number of stream characters the instance contains. */
    Size size() const { return _chain->size(); }

    /** Returns true if the instance's size is zero. */
    bool isEmpty() const { return _chain->size() == 0; }

    /**
     * Appends the content of a bytes instance. This function does not invalidate iterators.
     * @param data `Bytes` to append
     */
    void append(const Bytes& data);

    /**
     * Appends the content of a bytes instance. This function does not invalidate iterators.
     * @param data `Bytes` to append
     */
    void append(Bytes&& data);

    /**
     * Appends the content of a raw memory area, taking ownership. This function does not invalidate iterators.
     * @param data pointer to `Bytes` to append
     */
    void append(std::unique_ptr<const Byte*> data);

    /** Appends the content of a raw memory area, copying the data. This function does not invalidate iterators.
     * @param data pointer to the data to append. If this is nullptr and gap will be appended instead.
     * @param len length of the data to append
     */
    void append(const char* data, size_t len);

    /**
     * Cuts off the beginning of the data up to, but excluding, a given
     * iterator. All existing iterators pointing beyond that point will
     * remain valid and keep their offsets the same. Trimming is permitted
     * even on frozen instances.
     *
     * @param i iterator one past the last data element to trim
     */
    void trim(const SafeConstIterator& i) { _chain->trim(i); }

    /** Freezes the instance. When frozen, no further data can be appended. */
    void freeze() { _chain->freeze(); }

    /** Unfreezes the instance so that more data can be appended again. */
    void unfreeze() { _chain->unfreeze(); }

    /** Returns true if the instance is currently frozen. */
    bool isFrozen() const { return _chain->isFrozen(); }

    /** Returns a safe iterator representing the first byte of the instance. */
    SafeConstIterator begin() const { return _chain->begin(); }

    /** Returns a safe iterator representing the end of the instance. */
    SafeConstIterator end() const { return _chain->end(); }

    /** Returns an unsafe iterator representing the first byte of the instance. */
    UnsafeConstIterator unsafeBegin() const { return _chain->unsafeBegin(); }

    /** Returns an unsafe iterator representing the end of the instance. */
    UnsafeConstIterator unsafeEnd() const { return _chain->unsafeEnd(); }

    /**
     * Returns an iterator representing a specific offset.
     * @param offset offset to use for the created iterator
     */
    SafeConstIterator at(const Offset& offset) const { return _chain->at(offset); }

    /** Returns the offset of the position one after the stream's last byte. */
    Offset endOffset() const { return _chain->endOffset(); }

    /**
     * Returns a view representing the entire instance.
     *
     * @param expanding if true, the returned view will automatically grow
     *                  along with the stream object if more data gets added.
     */
    View view(bool expanding = true) const { return expanding ? View(begin()) : View(begin(), end()); }

    bool operator==(const Bytes& other) const { return view() == other; }
    bool operator==(const Stream& other) const { return view() == other.view(); }
    bool operator==(const stream::View& other) const { return view() == other; }
    bool operator!=(const Bytes& other) const { return ! (*this == other); }
    bool operator!=(const Stream& other) const { return ! (*this == other); }
    bool operator!=(const stream::View& other) const { return ! (*this == other); }

    /**
     * For internal debugging: Returns the number of dynamic chunks
     * allocated.
     */
    int numberOfChunks() const { return _chain->numberOfChunks(); }

    /**
     * Prints out a debug rendering to the stream's internal representation.
     */
    void debugPrint(std::ostream& out) const;

    /**
     * Prints out a debug rendering to a stream's internal representation.
     */
    static void debugPrint(std::ostream& out, const stream::detail::Chain* chain);

private:
    Stream(Chunk&& ch) : _chain(make_intrusive<Chain>(std::make_unique<Chunk>(std::move(ch)))) {}

    ChainPtr _chain; // always non-null
};

template<>
inline std::string detail::to_string_for_print<stream::View>(const stream::View& x) {
    return escapeBytes(x.dataForPrint(), true);
}

template<>
inline std::string detail::to_string_for_print<Stream>(const Stream& x) {
    return to_string_for_print(x.view());
}

inline std::ostream& operator<<(std::ostream& out, const Stream& x) { return out << to_string_for_print(x); }

namespace detail::adl {
inline std::string to_string(const stream::View& x, adl::tag /*unused*/) {
    return fmt("b\"%s\"", hilti::rt::to_string_for_print(x));
}

inline std::string to_string(const Stream& x, adl::tag /*unused*/) { return hilti::rt::to_string(x.view()); }
} // namespace detail::adl

} // namespace hilti::rt
