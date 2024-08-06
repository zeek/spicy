// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
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
struct NonOwning {};

namespace detail {
class UnsafeConstIterator;
}

/**
 * Accumulates statistics about a stream's data over its lifetime. Empty chunks
 * are not counted.
 */
struct Statistics {
    uint64_t num_data_bytes = 0;
    uint64_t num_data_chunks = 0;
    uint64_t num_gap_bytes = 0;
    uint64_t num_gap_chunks = 0;

    friend bool operator==(const Statistics& a, const Statistics& b) {
        return a.num_data_bytes == b.num_data_bytes && a.num_data_chunks == b.num_data_chunks &&
               a.num_gap_bytes == b.num_gap_bytes && a.num_gap_chunks == b.num_gap_chunks;
    }

    friend bool operator!=(const Statistics& a, const Statistics& b) { return ! (a == b); }

    Statistics& operator+=(Statistics& other) {
        num_data_bytes += other.num_data_bytes;
        num_data_chunks += other.num_data_chunks;
        num_gap_bytes += other.num_gap_bytes;
        num_gap_chunks += other.num_gap_chunks;
        return *this;
    }
};

} // namespace stream

namespace detail::adl {
std::string to_string(const Stream& x, adl::tag /*unused*/);
std::string to_string(const stream::View& x, adl::tag /*unused*/);
std::string to_string(const stream::SafeConstIterator& x, adl::tag /*unused*/);
std::string to_string(const stream::detail::UnsafeConstIterator& x, adl::tag /*unused*/);
std::string to_string(const stream::Statistics& x, adl::tag /*unused*/);
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
 * A chunk may or may not own its data. The former is the default for
 * construction and extension, unless specified explicitly otherwise. When
 * non-owning, the creator needs to ensure the data stays around as long as the
 * chunk does.
 *
 * All public methods of Chunk are constant. Modifications can be done only
 * be through the owning Chain (so that we can track changes there).
 */
class Chunk {
public:
    Chunk(const Offset& o, const View& d);
    Chunk(const Offset& o, std::string_view s);

    // Constructs a chunk that own its data by copying what's passed in.
    Chunk(const Offset& o, const Byte* b, size_t size);

    // Constructs a chunk that does not own its data.
    Chunk(const Offset& o, const Byte* b, size_t size, NonOwning);

    // Constructs a gap chunk which signifies empty data.
    Chunk(const Offset& o, size_t len);

    Chunk(const Chunk& other);

    Chunk(Chunk&& other) noexcept;

    Chunk& operator=(const Chunk& other);

    Chunk& operator=(Chunk&& other) noexcept;

    ~Chunk();

    Offset offset() const;
    Offset endOffset() const;
    bool isGap() const;
    bool isOwning() const;
    bool inRange(const Offset& offset) const;

    const Byte* data() const;

    const Byte* data(const Offset& offset) const;

    const Byte* endData() const;

    Size size() const;
    Size allocated() const;

    bool isLast() const;
    const Chunk* next() const;

    const Chunk* last() const;
    Chunk* last();

    // Creates a new copy of the data internally if the chunk is currently not
    // owning it. On return, is guaranteed to now own the data.
    void makeOwning();

    void debugPrint(std::ostream& out) const;

protected:
    // All mutating functions are protected and are expected to be called
    // only from chain so that it can track any changes.
    friend class Chain;

    // Update offset for current chunk and all others linked from it.
    void setOffset(Offset o);

    // Set chain for current chunk and all others linked from it.
    void setChain(const Chain* chain);

    Chunk* next();

    // Link in chunk as successor of current one. Updates offset/chain for the
    // appended chunk and all its successors. Makes the current chunk owning,
    // so that at most the last chunk in a chain can be non-owning.
    void setNext(std::unique_ptr<Chunk> next);

    // Reset chunk state to no longer reference a chain. Note that this does
    // not update its predecessor inside the chain if that exists.
    void detach();

private:
    Chunk();

    // Deletes all allocated/owned data, safely. Members will be left in
    // undefined state afterwards and need re-initialization if instance
    // remains in use.
    void destroy();

    Offset _offset = 0;            // global offset of 1st byte
    size_t _size = 0;              // size of payload or gap
    size_t _allocated = 0;         // size of memory allocated for data, which can be more than its size
    const Byte* _data = nullptr;   // chunk's payload, or null for gap chunks
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

    Chain();

    /** Moves a chunk and all its successors into a new chain. */
    Chain(std::unique_ptr<Chunk> head);

    Chain(Chain&& other) = delete;
    Chain(const Chain& other) = delete;
    Chain& operator=(const Chain& other) = delete;
    Chain& operator=(const Chain&& other) = delete;

    const Chunk* head() const;
    const Chunk* tail() const;
    Chunk* tail();
    Size size() const;
    bool isFrozen() const;
    bool isValid() const;
    bool inRange(const Offset& o) const;

    Offset offset() const;
    Offset endOffset() const;

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

    // Returns a newly allocated chain with the same content and statistics.
    ChainPtr copy() const;

    // Appends a new chunk to the end, copying the data.
    void append(const Byte* data, size_t size);

    // Appends a new chunk to the end, not copying the data.
    void append(const Byte* data, size_t size, stream::NonOwning);

    // Appends a new chunk to the end, moving the data.
    void append(Bytes&& data);

    // Appends another chain to the end.
    void append(Chain&& other);

    // Appends a new chunk to the end.
    void append(std::unique_ptr<Chunk> chunk);

    // Appends a gap to the end.
    void appendGap(size_t size);

    void trim(const Offset& offset);
    void trim(const SafeConstIterator& i);
    void trim(const UnsafeConstIterator& i);

    // Turns the chain into invalidated state, will releases all chunks and
    // will let attempts to dereference any still existing iterators fail.
    void invalidate();

    // Turns the chain into a freshly initialized state.
    void reset();

    void freeze();

    void unfreeze();

    // Returns the number of dynamic chunks allocated.
    int numberOfChunks() const;

    // Returns statistics for the chain. These are accumulative over the whole
    // lifetime of the chain.
    const stream::Statistics& statistics() const;

private:
    void _ensureValid() const;

    void _ensureMutable() const;

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

    // Tracks statistics as new data comes in.
    stream::Statistics _statistics;

    std::unique_ptr<Chunk> _cached; // previously freed chunk for reuse
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
    using ChainPtr = stream::detail::ChainPtr;
    using Chunk = stream::detail::Chunk;
    using Offset = stream::Offset;
    using Size = stream::Size;
    using UnsafeConstIterator = stream::detail::UnsafeConstIterator;

    /** Constructor. */
    SafeConstIterator() = default;

    SafeConstIterator(const SafeConstIterator&) = default;
    SafeConstIterator(SafeConstIterator&&) = default;

    SafeConstIterator& operator=(const SafeConstIterator&) = default;
    SafeConstIterator& operator=(SafeConstIterator&&) = default;

    /** Constructor. */
    explicit SafeConstIterator(const UnsafeConstIterator& i);

    /** Returns the offset inside the stream that the iterator represents. */
    Offset offset() const;

    /** Returns true if the stream instance that the iterator is bound to has been frozen.  */
    bool isFrozen() const;

    /** Advances the iterator by one byte. */
    SafeConstIterator& operator++();

    /** Advances the iterator by one byte. */
    SafeConstIterator operator++(int);

    /** Advances the iterator by a given number of stream. */
    SafeConstIterator& operator+=(const integer::safe<uint64_t>& i);

    /** Moves back the iterator by one byte. */
    SafeConstIterator& operator--();

    /** Moves back the iterator by one byte. */
    SafeConstIterator operator--(int);

    /** Moves back the iterator by a given number of stream. */
    SafeConstIterator& operator-=(const integer::safe<uint64_t>& i);

    /** Returns the character at the iterator's position. */
    Byte operator*() const;

    /** Return a new iterator advanced by a given number of bytes. */
    SafeConstIterator operator+(const integer::safe<uint64_t>& i) const;

    /** Returns a new iterator moved back by a given number of bytes. */
    SafeConstIterator operator-(const integer::safe<uint64_t>& i) const;

    /**
     * Return the size of the range defined by the two iterators. The result
     * will be negative if the instance's location comes before the
     * argument's location.
     */
    integer::safe<int64_t> operator-(const SafeConstIterator& other) const;

    /**
     * Returns true if another iterator bound to the same stream instance
     * refers to the same location. The result is undefined if the iterators
     * aren't referring to the same stream instance.
     */
    bool operator==(const SafeConstIterator& other) const;

    /**
     * Returns true if another iterator bound to the same stream instance does
     * not refer to the same location. The result is undefined if the
     * iterators aren't referring to the same stream instance.
     */
    bool operator!=(const SafeConstIterator& other) const;

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator<(const SafeConstIterator& other) const;

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator<=(const SafeConstIterator& other) const;

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator>(const SafeConstIterator& other) const;

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator>=(const SafeConstIterator& other) const;

    /** Returns true if the iterator is bound to a stream instance, even if expired. */
    explicit operator bool() const;

    std::ostream& operator<<(std::ostream& out) const;

    /** Returns true if the iterator remains unbound. */
    bool isUnset() const;

    /**
     * Returns true if the iterator was once valid but the underlying bytes
     * instance has by now expired.
     */
    bool isExpired() const;

    /**
     * Returns true if the iterator is bound to a stream object and that's
     * not expired yet.
     */
    bool isValid() const;

    /**
     * Returns true if the iterator is at or beyond the current end of the
     * underlying stream instance. Also generally returns true for an unbound
     * iterator.
     */
    bool isEnd() const;

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
    const Chunk* chunk() const;
    const Chain* chain() const;

private:
    SafeConstIterator(ChainPtr chain, const Offset& offset, const Chunk* chunk);

    void _ensureValidChain() const;

    void _ensureSameChain(const SafeConstIterator& other) const;

    void _increment(const integer::safe<uint64_t>& n);

    void _decrement(const integer::safe<uint64_t>& n);

    Byte _dereference() const;

    // Parent chain if bound, or null if not. The parent will stay around for
    // at least as long as this iterator.
    ChainPtr _chain = nullptr;

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

std::ostream& operator<<(std::ostream& out, const SafeConstIterator& x);

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
    using ChainPtr = stream::detail::ChainPtr;
    using Chunk = stream::detail::Chunk;
    using Offset = stream::Offset;
    using Size = stream::Size;

    /** Constructor. */
    UnsafeConstIterator() = default;

    /** Constructor. */
    explicit UnsafeConstIterator(const SafeConstIterator& i);

    /** Returns the offset inside the stream that the iterator represents. */
    Offset offset() const;

    /** Returns true if the stream instance that the iterator is bound to has been frozen.  */
    bool isFrozen() const;

    /** Advances the iterator by one byte. */
    UnsafeConstIterator& operator++();

    /** Advances the iterator by one byte. */
    UnsafeConstIterator operator++(int);

    /** Moves back the iterator by one byte. */
    UnsafeConstIterator& operator--();

    /** Moves back the iterator by one byte. */
    UnsafeConstIterator operator--(int);

    /** Moves back the iterator by a given number of stream. */
    UnsafeConstIterator& operator-=(const integer::safe<uint64_t>& i);

    /** Returns the character at the iterator's position. */
    Byte operator*() const;

    /** Return a new iterator advanced by a given number of bytes. */
    UnsafeConstIterator operator+(const integer::safe<uint64_t>& i) const;

    /** Return a new iterator moved back by a given number of bytes. */
    UnsafeConstIterator operator-(const integer::safe<uint64_t>& i) const;

    /**
     * Return the size of the range defined by the two iterators. The result
     * will be negative if the instance's location comes before the
     * argument's location.
     */
    integer::safe<int64_t> operator-(const UnsafeConstIterator& other) const;

    /**
     * Returns true if another iterator bound to the same stream instance
     * refers to the same location. The result is undefined if the iterators
     * aren't referring to the same stream instance.
     */
    bool operator==(const UnsafeConstIterator& other) const;

    /**
     * Returns true if another iterator bound to the same stream instance does
     * not refer to the same location. The result is undefined if the
     * iterators aren't referring to the same stream instance.
     */
    bool operator!=(const UnsafeConstIterator& other) const;

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator<(const UnsafeConstIterator& other) const;

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator<=(const UnsafeConstIterator& other) const;

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator>(const UnsafeConstIterator& other) const;

    /** Compares the offset of two iterators referring to the same stream instance. */
    bool operator>=(const UnsafeConstIterator& other) const;

    /** Returns true if the iterator is bound to a stream instance, even if expired. */
    explicit operator bool() const;

    std::ostream& operator<<(std::ostream& out) const;

    /** Returns true if the iterator remains unbound. */
    bool isUnset() const;

    /**
     * Returns true if the iterator was once valid but the underlying bytes
     * instance has by now expired.
     */
    bool isExpired() const;

    /**
     * Returns true if the iterator is bound to a stream object and that's
     * not expired yet.
     */
    bool isValid() const;

    /** Returns true if the iterator is at or beyond the current end of the underlying stream instance. */
    bool isEnd() const;

    /**
     * Prints out a debug rendering to the iterator's internal
     * representation.
     */
    void debugPrint(std::ostream& out) const;

protected:
    friend class hilti::rt::stream::View;
    friend class hilti::rt::stream::detail::Chain;
    friend class hilti::rt::stream::SafeConstIterator;

    const Chunk* chunk() const;
    const Chain* chain() const;

private:
    UnsafeConstIterator(const ChainPtr& chain, const Offset& offset, const Chunk* chunk);
    UnsafeConstIterator(const Chain* chain, const Offset& offset, const Chunk* chunk);

    void _increment(const integer::safe<uint64_t>& n);
    void _decrement(const integer::safe<uint64_t>& n);
    Byte _dereference() const;

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

std::ostream& operator<<(std::ostream& out, const UnsafeConstIterator& x);

} // namespace detail

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

    View(const View&) = default;
    View(View&&) = default;

    View& operator=(const View&) = default;
    View& operator=(View&&) = default;

    /** Constructor for static view bracketed through two iterators. */
    explicit View(SafeConstIterator begin, SafeConstIterator end);

    /**
     * Constructor for an expanding view that will always reflect a range up
     * to the current end of the underlying stream object, including when that
     * expands.
     */
    explicit View(SafeConstIterator begin);

    /**
     * Returns the offset of the view's starting location within the associated
     * stream instance.
     */
    Offset offset() const;

    /**
     * Returns the offset of the view's end location within the associated
     * stream instance. For an open-ended view, returns an unset value.
     */
    std::optional<Offset> endOffset() const;

    /**
     * Returns the number of actual bytes available inside the view. If the
     * view's end position is beyond the current end offset of the underlying
     * stream, those missing bytes are not counted.
     */
    Size size() const;

    /** Returns true if the view's size is zero. */
    bool isEmpty() const;

    /**
     * Returns true if the view's data is fully available, and won't change
     * anymore. That's the case if either the underlying stream is frozen, or
     * if the view is not open-ended and the iterator window is fully
     * contained inside the stream data available at this point.
     */
    bool isComplete() const;

    /**
     * Returns true if the view was constructed without a fixed end offset,
     * meaning it will expand as more data gets added to the underlying
     * stream.
     */
    bool isOpenEnded() const;

    /**
     * Returns the position of the first occurrence of a byte inside the
     * view. Will return *end()* if not found.
     *
     * @param b byte to search
     */
    SafeConstIterator find(Byte b) const;

    /**
     * Returns the position of the first occurrence of a byte inside the
     * view. Will return *end()* if not found.
     *
     * @param b byte to search
     * @param n starting point, which must be inside the view
     */
    SafeConstIterator find(Byte b, const SafeConstIterator& n) const;

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
    std::tuple<bool, SafeConstIterator> find(const View& v) const;

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
    std::tuple<bool, SafeConstIterator> find(const View& v, const SafeConstIterator& n) const;

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
    std::tuple<bool, SafeConstIterator> find(const Bytes& v, Direction d = Direction::Forward) const;

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
                                             Direction d = Direction::Forward) const;

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
                                               Direction d = Direction::Forward) const;

    /**
     * Advances the view's starting position to a new place.
     *
     * @param i the new position, which must be inside the current view
     * @return the modified view
     */
    View advance(SafeConstIterator i) const;

    /**
     * Advances the view's starting position by a given number of stream bytes.
     *
     * @param i the number of stream bytes to advance.
     */
    View advance(const integer::safe<uint64_t>& i) const;

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
    View sub(SafeConstIterator from, SafeConstIterator to) const;

    /**
     * Extracts subrange of bytes from the beginning of the view, returned as
     * a new view.
     *
     * @param to iterator pointing to just beyond subrange
     */
    View sub(SafeConstIterator to) const;

    /**
     * Extracts subrange of bytes from the view, returned as a new view.
     *
     * @param from offset of start of subrange, relative to beginning of view
     * @param to offset of one beyond end of subrange, relative to beginning of view
     */
    View sub(const Offset& from, const Offset& to) const;

    /**
     * Extracts subrange of stream from the beginning of the view, returned as
     * a new view.
     *
     * @param to of one beyond end of subrange, relative to beginning of view
     */
    View sub(const Offset& to) const;

    /** Returns an iterator representing an offset inside the view's data */
    SafeConstIterator at(const Offset& offset) const;

    /**
     * Returns a new view moves the beginning to a subsequent iterator while
     * not changing the end. In particular, this maintains a view capability
     * to expand to an underlying data instance's growth.
     */
    View trim(const SafeConstIterator& nbegin) const;

    /**
     * Returns a new view that keeps the current start but cuts off the end
     * at a specified offset from that beginning. The returned view will not
     * be able to expand any further.
     */
    View limit(Offset offset) const;

    /**
     * Extracts a fixed number of stream bytes from the view.
     *
     * @param dst target array to write stream data into
     * @param n number of stream bytes to extract
     * @return new view that has it's starting position advanced by N
     */
    View extract(Byte* dst, uint64_t n) const;

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
    detail::UnsafeConstIterator unsafeBegin() const;

    /** Returns an unsafe iterator representing the end of the instance. */
    detail::UnsafeConstIterator unsafeEnd() const;

    /** Returns an safe iterator pointint to the beginning of the view. */
    const SafeConstIterator& begin() const;

    /** Same as `begin()`, just for compatibility with std types. */
    const SafeConstIterator& cbegin() const;

    /** Returns a safe iterator representing the end of the instance. */
    SafeConstIterator end() const;

    /** Same as `end()`, just for compatibility with std types. */
    SafeConstIterator cend() const;

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
    bool operator!=(const Bytes& other) const;
    bool operator!=(const Stream& other) const;
    bool operator!=(const View& other) const;

    /**
     * Prints out a debug rendering to the view's internal representation.
     */
    void debugPrint(std::ostream& out) const;

private:
    View(SafeConstIterator begin, std::optional<SafeConstIterator> end);

    void _ensureSameChain(const SafeConstIterator& other) const;

    void _ensureValid() const;

    virtual void _force_vtable(); // force creation of consistent vtable for RTTI; not used otherwise

    // Common backend for backward searching.
    std::tuple<bool, UnsafeConstIterator> _findBackward(const Bytes& needle, UnsafeConstIterator i) const;

    // Common backend for forward searching.
    std::tuple<bool, UnsafeConstIterator> _findForward(const Bytes& v, UnsafeConstIterator n) const;

    SafeConstIterator _begin;
    std::optional<SafeConstIterator> _end;
};

std::ostream& operator<<(std::ostream& out, const View& x);
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
    Stream();

    /**
     * Creates an instance from a bytes instance.
     * @param d `Bytes` instance to the create the stream from
     */
    explicit Stream(Bytes d);

    /**
     * Creates an instance from an existing memory block. The data
     * will be copied if set, otherwise a gap will be recorded.
     */
    Stream(const char* d, Size n);

    /**
     * Creates an instance from an existing memory block. The data will not be
     * copied and hence must remain valid until the stream ether is destroyed
     * or `makeOwning()` gets called, whatever comes first. Passing a nullptr
     * for the data records a gap.
     */
    Stream(const char* d, Size n, stream::NonOwning);

    /**
     * Creates an instance from an existing stream view.
     * @param d `View` to create the stream from
     */
    Stream(const stream::View& d);

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
    Stream(const Stream& other);

    /**
     * Constructs a stream from another stream instance.
     * @param other instance to create this stream from
     */
    Stream(Stream&& other) noexcept;

    /**
     * Assigns from another stream instance. This invalidates all existing iterators.
     * @param other the stream instance to assign from
     */
    Stream& operator=(Stream&& other) noexcept;

    /**
     * Assigns from another stream instance. This invalidates all existing iterators.
     * @param other the stream instance to assign from
     */
    Stream& operator=(const Stream& other);

    /** Destructor. */
    ~Stream();

    /** Returns the number of stream characters the instance contains. */
    Size size() const;

    /** Returns true if the instance's size is zero. */
    bool isEmpty() const;

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

    /**
     * Appends the content of a raw memory area, copying the data. This
     * function does not invalidate iterators.
     * @param data pointer to the data to append. If this is nullptr and gap will be appended instead.
     * @param len length of the data to append
     */
    void append(const char* data, size_t len);


    /**
     * Appends the content of a raw memory area, *not* copying the data. This
     * function does not invalidate iterators. Because the data will not be
     * copied, it must remain valid until the stream is either destroyed or
     * `makeOwning()` gets called.
     *
     * @param data pointer to the data to append. If this is nullptr and gap will be appended instead.
     * @param len length of the data to append
     */
    void append(const char* data, size_t len, stream::NonOwning);

    /**
     * Cuts off the beginning of the data up to, but excluding, a given
     * iterator. All existing iterators pointing beyond that point will
     * remain valid and keep their offsets the same. Trimming is permitted
     * even on frozen instances.
     *
     * @param i iterator one past the last data element to trim
     */
    void trim(const SafeConstIterator& i);

    /** Freezes the instance. When frozen, no further data can be appended. */
    void freeze();

    /** Unfreezes the instance so that more data can be appended again. */
    void unfreeze();

    /** Returns true if the instance is currently frozen. */
    bool isFrozen() const;

    /**
     * Returns the stream into a freshly initialized state, as if it was just
     * created. (This concerns only externally visible state, it retains any
     * potentially cached resources for reuse.)
     */
    void reset();

    /** Ensure the stream fully owns all its data. */
    void makeOwning();

    /** Returns a safe iterator representing the first byte of the instance. */
    SafeConstIterator begin() const;
    SafeConstIterator cbegin() const;

    /** Returns a safe iterator representing the end of the instance. */
    SafeConstIterator end() const;
    SafeConstIterator cend() const;

    /** Returns an unsafe iterator representing the first byte of the instance. */
    UnsafeConstIterator unsafeBegin() const;

    /** Returns an unsafe iterator representing the end of the instance. */
    UnsafeConstIterator unsafeEnd() const;

    /**
     * Returns an iterator representing a specific offset.
     * @param offset offset to use for the created iterator
     */
    SafeConstIterator at(const Offset& offset) const;

    /** Returns the offset of the position one after the stream's last byte. */
    Offset endOffset() const;

    /**
     * Returns a view representing the entire instance.
     *
     * @param expanding if true, the returned view will automatically grow
     *                  along with the stream object if more data gets added.
     */
    View view(bool expanding = true) const;

    bool operator==(const Bytes& other) const;
    bool operator==(const Stream& other) const;
    bool operator==(const stream::View& other) const;
    bool operator!=(const Bytes& other) const;
    bool operator!=(const Stream& other) const;
    bool operator!=(const stream::View& other) const;

    /**
     * For internal debugging: Returns the number of dynamic chunks
     * allocated.
     */
    int numberOfChunks() const;

    /*
     * Returns statistics for the chain. These are accumulative over the whole
     * lifetime of the chain.
     */
    const stream::Statistics& statistics() const;

    /**
     * Prints out a debug rendering to the stream's internal representation.
     */
    void debugPrint(std::ostream& out) const;

    /**
     * Prints out a debug rendering to a stream's internal representation.
     */
    static void debugPrint(std::ostream& out, const stream::detail::Chain* chain);

private:
    Stream(Chunk&& ch);

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

std::ostream& operator<<(std::ostream& out, const Stream& x);
std::ostream& operator<<(std::ostream& out, const stream::Statistics& x);

} // namespace hilti::rt
