// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

// TODO(robin): These classes need a cleanup. The current structure is still an
// artifact of previousky having just a single type for bytes and streams.

#pragma once

#include <any>
#include <utility>
#include <variant>

#include <array>
#include <cinttypes>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <hilti/rt/exception.h>
#include <hilti/rt/result.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

class Bytes;

class Stream;
namespace stream {
class View;
} // namespace stream
namespace stream {
class SafeConstIterator;
} // namespace stream

namespace detail::adl {
extern std::string to_string(const Stream& x, adl::tag /*unused*/);
extern std::string to_string(const stream::View& x, adl::tag /*unused*/);
extern std::string to_string(const stream::SafeConstIterator& x, adl::tag /*unused*/);
} // namespace detail::adl

namespace stream {

/** A single element inside a stream instance. */
using Byte = uint8_t;

/** Offset within a stream instance. */
using Offset = integer::safe<uint64_t>;

/** Size of a stream instance in numer of elements stores. */
using Size = integer::safe<uint64_t>;

/**
 * Exception reflecting an attempt to modify a stream object that's been frozen.
 */
HILTI_EXCEPTION(Frozen, RuntimeError)

namespace detail {

class UnsafeConstIterator;

/**
 * One block of continous data inside a stream instance. A stream instance
 * chains these to represent all of its content.
 */
class Chunk {
public:
    static const int SmallBufferSize = 32;
    using Array = std::pair<Size, std::array<Byte, SmallBufferSize>>;
    using Vector = std::vector<Byte>;

    Chunk() : _data(Array()) {}
    Chunk(Offset o, std::array<Byte, SmallBufferSize>&& d, Size n) : _offset(o), _data(std::make_pair(n, d)) {}
    Chunk(Offset o, Vector&& d) : _offset(o), _data(std::move(d)) {}
    Chunk(const View& d);
    Chunk(const std::string& s);
    Chunk(const Chunk& other) : _offset(other._offset), _data(other._data) {}
    Chunk(Chunk&& other) noexcept : _offset(other._offset), _data(std::move(other._data)) {}
    ~Chunk() = default;

    Chunk& operator=(const Chunk& other) {
        _offset = other._offset;
        _data = other._data;
        return *this;
    }
    Chunk& operator=(Chunk&& other) noexcept {
        _offset = other._offset;
        _data = std::move(other._data);
        return *this;
    }

    Offset offset() const { return _offset; }
    bool isCompact() const { return std::holds_alternative<Array>(_data); }

    const Byte* begin() const {
        if ( auto a = std::get_if<Array>(&_data) )
            return a->second.data();

        auto& v = std::get<Vector>(_data);
        return v.data();
    }

    const Byte* end() const {
        if ( auto a = std::get_if<Array>(&_data) )
            return a->second.data() + a->first.Ref();

        auto& v = std::get<Vector>(_data);
        return v.data() + v.size();
    }

    Size size() const {
        if ( auto a = std::get_if<Array>(&_data) )
            return a->first;

        auto& v = std::get<Vector>(_data);
        return v.size();
    }

    Byte at(Offset o) const { return *data(o); }

    const Byte* data(Offset o) const {
        auto c = this;

        while ( o < c->_offset || o >= c->_offset + c->size() ) {
            if ( ! c->_next )
                throw InvalidIterator("offset outside of valid range (1)");

            c = c->next().get();
        }

        return c->begin() + (o - c->_offset).Ref();
    }

    void freeze() { _frozen = true; }
    void unfreeze() { _frozen = false; }
    bool isFrozen() const { return _frozen; }

    bool isLast() const { return _next == nullptr; }
    const std::shared_ptr<Chunk>& next() const { return _next; }
    auto last() const {
        std::shared_ptr<Chunk> i = _next;
        while ( i && i->_next )
            i = i->_next;
        return i;
    }

    void clearNext() { _next = nullptr; }
    void setNext(std::shared_ptr<Chunk> c) { _next = std::move(c); }
    void setOffset(Offset o) { _offset = o; }
    bool tryAppend(const Chunk& d); // Appends to small buffer is possible, returns false of not.
    void trim(Offset o);

    void debugPrint(std::ostream& out) const;

private:
    Byte* begin() {
        if ( auto a = std::get_if<Array>(&_data) )
            return a->second.data();

        auto& v = std::get<Vector>(_data);
        return v.data();
    }

    // Note: We must not have a pointer to the parent stream instance in
    // chunks because the parent may be on the stack with a shorter life
    // time.
    Offset _offset = 0;
    std::variant<Array, Vector> _data;
    std::shared_ptr<Chunk> _next = nullptr;
    bool _frozen = false;

    // TODO(robin): Implement later.
    //  std::optional<Object> object;
    //  std::vector<std::int64_t> marks; // offsets relative to this chunk
};

/** The main content structure for a heap-allocated stream object. */
struct Chain {
    std::shared_ptr<Chunk> head;
    std::shared_ptr<Chunk> tail;

    Chain(Chunk&& ch) : head(std::make_shared<Chunk>(std::move(ch))), tail(head) {}
    Chain(const std::string& data) : head(std::make_shared<Chunk>(data)), tail(head) {}
    Chain(std::shared_ptr<Chunk>&& head, std::shared_ptr<Chunk>&& tail)
        : head(std::move(head)), tail(std::move(tail)) {}
};

} // namespace detail

/**
 * SafeConstIterator for traversing the content of a stream instance.
 *
 * Unlike the standard `Iterator`, this iterator version protects against the
 * stream instance being no longer available by throwing an `InvalidIterator`
 * exception if it's still accessed.
 *
 * A safe iterator can also be advanced beyond the end of a stream instead.
 * If the instance gets expanded later, the iterator will be refer to that
 * new data.
 */
class SafeConstIterator {
public:
    SafeConstIterator() = default;

    /** Returns the offset inside the stream that iterator represents. */
    Offset offset() const { return _offset; }

    /** Returns true if the stream instance that the iterator is bound to has been frozen.  */
    bool isFrozen() const { return chunk()->isFrozen(); }

    /**
     * Returns an iterator corresponding to the end position of the
     * underlying stream object.
     */
    SafeConstIterator end() const {
        check();

        SafeConstIterator e;

        if ( isEnd() )
            e = *this;
        else if ( chunk()->isLast() )
            e = {_content, chunk()->offset() + chunk()->size(), _chunk};
        else {
            auto l = chunk()->last();
            assert(l);
            assert(l->isLast());
            e = {_content, l->offset() + l->size(), l};
        }

        assert(e.isEnd());
        return e;
    }

    /** Advances the iterator by one byte. */
    auto& operator++() {
        check();
        increment(1);
        return *this;
    }

    /** Advances the iterator by one byte. */
    auto operator++(int) { // NOLINT
        auto x = *this;
        increment(1);
        return x;
    }

    /** Advances the iterator by a given number of stream. */
    auto& operator+=(integer::safe<uint64_t> i) {
        check();
        increment(i);
        return *this;
    }

    /** Returns the character at the iterator's position. */
    auto operator*() const {
        check();
        return dereference();
    }

    /** Return a new iterator advanced by a given number of stream. */
    auto operator+(integer::safe<uint64_t> i) const { return SafeConstIterator(*this) += i; }

    /**
     * Return the size of the range defined by the two iterators. The result
     * will be negative if the instances's location comes before the
     * arguments's location.
     */
    integer::safe<int64_t> operator-(const SafeConstIterator& other) const {
        return static_cast<int64_t>(offset()) - static_cast<int64_t>(other.offset());
    }

    /**
     * Returns true if another iterator bound to the same stream instance
     * refers to the same location. The result is undefined if the iterators
     * aren't refering to the same stream instance.
     */
    bool operator==(const SafeConstIterator& other) const {
        check();
        other.check();
        return (_offset == other._offset) || (isEnd() && other.isEnd());
    }

    /**
     * Returns true if another iterator bound to the same stream instance does
     * not refer to the same location. The result is undefined if the
     * iterators aren't refering to the same stream instance.
     */
    bool operator!=(const SafeConstIterator& other) const { return ! (*this == other); }

    /** Compares the offset of two iterators refering to the same stream instance. */
    bool operator<(const SafeConstIterator& other) const { return offset() < other.offset(); }

    /** Compares the offset of two iterators refering to the same stream instance. */
    bool operator<=(const SafeConstIterator& other) const { return offset() <= other.offset(); }

    /** Compares the offset of two iterators refering to the same stream instance. */
    bool operator>(const SafeConstIterator& other) const { return offset() > other.offset(); }

    /** Compares the offset of two iterators refering to the same stream instance. */
    bool operator>=(const SafeConstIterator& other) const { return offset() >= other.offset(); }

    /** Returns true if the iterator is bound to a stream instance. */
    explicit operator bool() const { return ! isUnset(); }

    std::ostream& operator<<(std::ostream& out) const {
        out << to_string(*this);
        return out;
    }

    void* chain() const { return content(); }

    /** Returns true if the iterator remains unintialized. */
    bool isUnset() const {
        const auto unset = std::weak_ptr<detail::Chain>();
        return ! (_content.owner_before(unset) || unset.owner_before(_content));
    }

    /** Returns true if the iterator is at or beyond the current end of the underlying stream instance. */
    bool isEnd() const { return (! chunk()) || (chunk()->isLast() && _offset >= chunk()->offset() + chunk()->size()); }

    /**
     * Returns true if the iterator was once valid but the underlying btes
     * instance has by now expired.
     */
    bool isExpired() const {
        normalize();

        if ( ! _chunk.expired() )
            return false;

        if ( isUnset() )
            return false;

        if ( content()->head && _offset >= content()->head->offset() )
            return false;

        return true;
    }

    void debugPrint(std::ostream& out) const;

private:
    friend class hilti::rt::Stream;
    friend class hilti::rt::stream::View;
    friend class hilti::rt::stream::detail::UnsafeConstIterator;

    SafeConstIterator(std::weak_ptr<detail::Chain> content, Offset offset, std::weak_ptr<detail::Chunk> chunk)
        : _content(std::move(content)), _offset(offset), _chunk(std::move(chunk)) {
        // Make sure _content is set.
        assert(! isUnset());
    }

    detail::Chunk* chunk() const {
        normalize();
        return _chunk.lock().get();
    }
    detail::Chain* content() const {
        normalize();
        return _content.lock().get();
    }

    void check() const {
        normalize();

        if ( ! _chunk.expired() )
            return;

        if ( isUnset() )
            throw InvalidIterator("not initialized");

        if ( _content.use_count() == 0 )
            throw InvalidIterator("deleted stream object");

        throw InvalidIterator("invalidated iterator");
    }

    void normalize() const {
        if ( ! isUnset() ) {
            if ( auto content = _content.lock().get(); content && content->head && _offset >= content->head->offset() )
                // New in-range data was appended but current chunk is expired.
                // Reinit from beginning of stream data.
                _chunk = content->head;
        }

        while ( auto chunk = _chunk.lock().get() ) {
            if ( chunk->isLast() || _offset < chunk->offset() + chunk->size() )
                break;

            _chunk = chunk->next();
        }
    }

    void increment(integer::safe<uint64_t> n) {
        _offset += n;
        normalize();
    }

    Byte dereference() const { return chunk()->at(_offset); }

    std::weak_ptr<detail::Chain> _content;       // Parent stream object.
    Offset _offset = 0;                          // Offset inside parent stream object.
    mutable std::weak_ptr<detail::Chunk> _chunk; // Current chunk
};

inline std::ostream& operator<<(std::ostream& out, const SafeConstIterator& x) {
    out << to_string(x);
    return out;
}

namespace detail {

/**
 * Standard iterator for internal usage. Unlike `SafeConstIterator`, this iterator
 * version is not safe against the underlying stream instances disappearing;
 * it will not catch that and likely cause a crash. When using this, one
 * hence needs to ensure that the stream instance will remain valid for at
 * least as long as the iterator (like with any standard C++ container). In
 * return, this iterator is more efficient than the `SafeConstIterator`.
 */
class UnsafeConstIterator {
public:
    UnsafeConstIterator() = default;
    explicit UnsafeConstIterator(const SafeConstIterator& i) {
        auto x = i;
        i.normalize();
        _content = i._content;
        _offset = i.offset();
        _shadow_chunk = i._chunk.lock();
        _chunk = _shadow_chunk.get();
    }

    Offset offset() const { return _offset; }

    /** Provides direct access to the current chunk. */
    const Chunk* chunk() const { return _chunk; }

    auto& operator++() {
        increment(1);
        return *this;
    }

    auto operator++(int) { // NOLINT
        const auto x = *this;
        increment(1);
        return x;
    }

    auto& operator+=(integer::safe<uint64_t> i) {
        increment(i);
        return *this;
    }

    auto operator*() const {
        assert(_chunk);
        return _chunk->at(_offset); // NOLINT
    }
    auto operator+(integer::safe<uint64_t> i) const { return (UnsafeConstIterator(*this) += i); }

    bool operator==(const UnsafeConstIterator& other) const {
        return (_offset == other._offset) || (isEnd() && other.isEnd());
    }

    bool operator==(const SafeConstIterator& other) const {
        return (_offset == other._offset) || (isEnd() && other.isEnd());
    }

    bool operator!=(const UnsafeConstIterator& other) const { return ! (*this == other); }
    bool operator!=(const SafeConstIterator& other) const { return ! (*this == other); }
    explicit operator bool() const { return _chunk != nullptr; }

    explicit operator SafeConstIterator() const {
        if ( ! _shadow_chunk )
            throw InvalidIterator("illegal iterator conversion");

        if ( ! _content.use_count() )
            hilti::rt::internalError("cannot convert stream::Iterator to stream::SafeConstIterator");

        return SafeConstIterator{_content, _offset, _shadow_chunk};
    }

    bool isEnd() const { return (! chunk()) || (chunk()->isLast() && _offset >= chunk()->offset() + chunk()->size()); }

    void debugPrint(std::ostream& out) const;

private:
    friend class hilti::rt::Stream;
    UnsafeConstIterator(std::weak_ptr<detail::Chain> content, Offset offset, const detail::Chunk* chunk)
        : _content(std::move(content)), _offset(offset), _chunk(chunk) {}

    void increment(integer::safe<uint64_t> n) {
        _offset += n;

        while ( _chunk && ! _chunk->isLast() && _offset >= _chunk->offset() + _chunk->size() ) {
            _chunk = _chunk->next().get();
            if ( _shadow_chunk )
                _shadow_chunk = _shadow_chunk->next();
        }
    }

    std::weak_ptr<detail::Chain> _content; // Parent stream object.
    Offset _offset = 0;
    std::shared_ptr<detail::Chunk> _shadow_chunk;
    const detail::Chunk* _chunk = nullptr;
};

} // namespace detail

namespace detail {
template<int N>
inline UnsafeConstIterator extract(Byte* dst, const UnsafeConstIterator& i, const SafeConstIterator& end) {
    if ( i == end )
        throw WouldBlock("end of stream views");

    *dst = *i;
    return extract<N - 1>(dst + 1, i + 1, end);
}

template<>
inline UnsafeConstIterator extract<0>(Byte* /* dst */, const UnsafeConstIterator& i,
                                      const SafeConstIterator& /* end */) {
    return i;
}

} // namespace detail

/**
 * A subrange of stream instance. The view is maintained through two safe
 * iterators; no data is copied. That makes the view cheap to create and pass
 * around. Because of the use of safe containers, it'll be caught through
 * `InvalidIterator` if the underlying stream instances goes away.
 */
class View {
public:
    View() = default;
    View(SafeConstIterator begin, SafeConstIterator end) : _begin(std::move(begin)), _end(std::move(end)) {}

    /**
     * Will always reflect a view to the end of the underlying stream object,
     * including when that expands.
     */
    explicit View(SafeConstIterator begin) : _begin(std::move(begin)) {}

    /**
     * Returns the offset of the view's starting location within the associated
     * stream instance.
     */
    Offset offset() const { return _begin.offset(); }

    /** Returns the number of bytes spanned by the view.  */
    Size size() const;

    /** Returns true if the view's size is zero. */
    bool isEmpty() const { return size() == 0; }

    /** Returns true if the instance is currently frozen. */
    bool isFrozen() const { return _begin.isFrozen(); }

    /** XXX */
    bool isOpenEnded() const { return ! _end.has_value(); }

    /**
     * Returns the position of the first occurence of a byte inside the view.
     *
     * @param b byte to search
     * @param n optional starting point, which must be inside the vier
     */
    SafeConstIterator find(Byte b, const SafeConstIterator& n = SafeConstIterator()) const;

    /**
     * Searches for the first occurence of another view's data.
     *
     * @param v data to search for
     * @param n optional starting point, which must be inside this view
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st stream;
     * if no, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*.
     */
    std::tuple<bool, SafeConstIterator> find(const View& v, const SafeConstIterator& n = SafeConstIterator()) const;

    /**
     * Searches for the first occurence of data.
     *
     * @param v data to search for
     * @param n optional starting point, which must be inside this view
     * @return tuple where the 1st element is a boolean indicating whether
     * *v* has been found; if yes, the 2nd element points to the 1st byte;
     * if no, the 2nd element points to the first byte so that no earlier
     * position has even a partial match of *v*.
     */
    std::tuple<bool, SafeConstIterator> find(const Bytes& v, const SafeConstIterator& n = SafeConstIterator()) const;

    /**
     * Advances the view's starting position to a new place.
     *
     * @param i the new position, which must be inside the current view
     * @return the modified view
     */
    View advance(SafeConstIterator i) const { return View(std::move(i), _end); }

    /**
     * Advances the view's starting position by a given number of stream.
     *
     * @param i the number of stream to advance.
     */
    View advance(integer::safe<uint64_t> i) const { return View(safeBegin() + i, _end); }

    /**
     * Extracts a subrange of bytes from the view, returned as a new view.
     *
     * @param from iterator pointing to start of subrange
     * @param to iterator pointing to just beyond subrange
     */
    View sub(SafeConstIterator from, SafeConstIterator to) const { return View(std::move(from), std::move(to)); }

    /**
     * Extracts subrange of bytes from the beginning of the view, returned as
     * a new view.
     *
     * @param to iterator pointing to just beyond subrange
     */
    View sub(SafeConstIterator to) const { return View(safeBegin(), std::move(to)); }

    /**
     * Extracts subrange of bytes from the view, returned as a new view.
     *
     * @param offset of start of subrage, relative to beginning of view
     * @param offset of one byeond end of subrage, relative to beginning of view
     */
    View sub(Offset from, Offset to) const { return View(safeBegin() + from, safeBegin() + to); }

    /**
     * Extracts subrange of stream from the beginning of the view, returned as
     * a new view.
     *
     * @param to of one byeond end of subrange, relative to beginning of view
     */
    View sub(Offset to) const { return View(safeBegin(), safeBegin() + to); }

    /** Returns an iterator representing an offset inside the view's data */
    SafeConstIterator at(Offset offset) const { return safeBegin() + (offset - safeBegin().offset()); }

    /**
     * Returns a new view moves the beginning to a subsequent iterator while
     * not changing the end. In particluar, this maintains a view capapbility
     * to expand to an underlying data instance's growth.
     */
    View trim(const SafeConstIterator& nbegin) const { return _end ? View(nbegin, *_end) : View(nbegin); }

    /**
     * Returns a new view that keeps the current start but cuts off the end
     * at a specified offset from that beginning. The returned view will not
     * be able to expand any further.
     */
    View limit(Offset incr) const { return View(safeBegin(), safeBegin() + incr); }

    /**
     * Extracts a fixed number of stream from the view.
     *
     * @tparam N number of stream to extract
     * @param dst attry to writes stream into
     * @return new view that has it's starting position advanced by N
     */
    template<int N>
    View extract(Byte (&dst)[N]) const {
        return View(SafeConstIterator(detail::extract<N>(dst, detail::UnsafeConstIterator(_begin), safeEnd())), _end);
    }

    /**
     * Copies the view into raw memory
     *
     * @param dst destination to write to, which must have at least `size()`
     * stream available().
     */
    void copyRaw(Byte* dst) const;

    /** Returns a copy of the data the view refers to. */
    std::string data() const;

    detail::UnsafeConstIterator begin() const {
        _begin.check();
        return detail::UnsafeConstIterator(_begin);
    }

    detail::UnsafeConstIterator end() const { return detail::UnsafeConstIterator(safeEnd()); }

    const SafeConstIterator& safeBegin() const { return _begin; }
    SafeConstIterator safeEnd() const { return _end ? *_end : _begin.end(); }

    void* chain() const { return _begin.chain(); }

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

    void debugPrint(std::ostream& out) const;

private:
    View(SafeConstIterator begin, std::optional<SafeConstIterator> end)
        : _begin(std::move(begin)), _end(std::move(end)) {}

    SafeConstIterator _begin;
    std::optional<SafeConstIterator> _end;
};

inline std::ostream& operator<<(std::ostream& out, const View& x) {
    out << x.data();
    return out;
}

} // namespace stream

/**
 * Container for raw binary data that's going to be processed in streaming
 * mode.. The underlying data storage is optimized for cheap append
 * operations even with large instances, but does not allow for modifications
 * of existing data. It also ensures that iterators bound to an instance can
 * reliably detect if the instance gets deleted.
 */
class Stream {
private:
    using Chunk = stream::detail::Chunk;
    using Byte = stream::Byte;
    using Offset = stream::Offset;
    using Size = stream::Size;

public:
    using const_iterator = stream::SafeConstIterator;

    Stream() : Stream(Chunk("")) {}

    /** Creates an instance from a vector of stream. */
    explicit Stream(std::vector<Byte> d) : Stream(Chunk(0, std::move(d))) {}

    /** Creates an instance from a bytes instance. */
    explicit Stream(const Bytes& d);

    /** Creates an instance for C-style ASCIIZ string, not including the final null byte. The data will be copied. */
    explicit Stream(const char* d) : Stream(chunkFromArray(0, d, strlen(d))) {}

    /** Creates an instance from an existing memory block. The data will be copied. */
    Stream(const char* d, Size n) : Stream(chunkFromArray(0, d, n)) {}

    /** Creates an instance from an existing stream view.  */
    Stream(const stream::View& d) : Stream(Chunk(d)) {}

    /** Creates an instance from a series of static-sized blocks. */
    template<int N>
    Stream(std::vector<std::array<Byte, N>> d) : Stream(chunkFromArray(0, std::move(d))) {}

    Stream(const Stream& other) noexcept : _content(other.deepCopyContent()), _frozen(other._frozen) {}
    Stream(Stream&& other) noexcept : _content(std::move(other._content)), _frozen(other._frozen) {}

    Stream& operator=(Stream&& other) noexcept {
        if ( &other == this )
            return *this;

        _content = std::move(other._content);
        _frozen = other._frozen;
        return *this;
    }

    Stream& operator=(const Stream& other) {
        if ( &other == this )
            return *this;

        _content = other.deepCopyContent();
        _frozen = other._frozen;
        return *this;
    }

    ~Stream() = default;

    /** Returns the number of stream characters the instance contains. */
    Size size() const { return tail()->offset() + tail()->size() - head()->offset(); }

    /** Returns true if the instance's size is zero. */
    bool isEmpty() const { return size() == 0; }

    /** For internal debugging: Returns the number of dynamic chunbks allocated. */
    int numberChunks() const;

    /** Appends the content of a bytes instance. */
    void append(const Bytes& data);

    /** Appends the content of a bytes instance. */
    void append(Bytes&& data);

    /** Appends the content of a raw memory area, taking ownership. */
    void append(std::unique_ptr<const Byte*> data);

    /** Appends the content of a raw memory area, copying the data. */
    void append(const char* data, size_t len);

    /**
     * Cuts off the beginning of the data up to, but excluding, a given
     * iterator. All existing iterators pointing beyond that point will
     * remain valid and keep their offsets the same. Trimming is permitted
     * even on frozen instances.
     */
    void trim(const stream::SafeConstIterator& i);

    /** Freezes the instance. When frozen, no further data can be appended. */
    void freeze();

    /** Unfreezes the instance so that more data can be appended again. */
    void unfreeze();

    /** Returns true if the instance is currently frozen. */
    bool isFrozen() const { return _frozen; }

    /** Returns an interator representing the first byte of the instance. */
    stream::SafeConstIterator safeBegin() const { return {_content, _content->head->offset(), _content->head}; }

    /** Returns an interator representing the end of the instance. */
    stream::SafeConstIterator safeEnd() const {
        auto& t = _content->tail;
        return {_content, t->offset() + t->size(), t};
    }

    /** Returns an interator representing a specific offset. */
    stream::SafeConstIterator at(Offset offset) const { return safeBegin() + (offset - safeBegin().offset()); }

    /**
     * Returns a view representing the entire instance.
     *
     * @param expanding if true, the returned view will automatically grow
     * along with the stream object if more data gets added.
     */
    stream::View view(bool expanding = true) const {
        if ( expanding )
            return stream::View(safeBegin());

        return stream::View(safeBegin(), safeEnd());
    }

    stream::detail::UnsafeConstIterator begin() const { return {{}, head()->offset(), head()}; }
    stream::detail::UnsafeConstIterator end() const {
        auto t = tail();
        return {{}, t->offset() + t->size(), t};
    }

    /** Returns a copy of the data the stream refers to. */
    std::string data() const;

    bool operator==(const Bytes& other) const { return view() == other; }
    bool operator==(const Stream& other) const { return view() == other.view(); }
    bool operator==(const stream::View& other) const { return view() == other; }
    bool operator!=(const Bytes& other) const { return ! (*this == other); }
    bool operator!=(const Stream& other) const { return ! (*this == other); }
    bool operator!=(const stream::View& other) const { return ! (*this == other); }

    void debugPrint(std::ostream& out) const;
    static void debugPrint(std::ostream& out, const stream::detail::Chain* chain);

private:
    friend class stream::View;
    using ChainPtr = std::shared_ptr<stream::detail::Chain>;
    using Content = ChainPtr;
    using UnsafeConstIterator = stream::detail::UnsafeConstIterator;

    Stream(Chunk&& ch) : _content(std::make_shared<stream::detail::Chain>(std::move(ch))) {}

    const Chunk* head() const { return _content->head.get(); }

    Chunk* head() { return _content->head.get(); }

    const Chunk* tail() const { return _content->tail.get(); }

    Chunk* tail() { return _content->tail.get(); }

    int compare(const Stream& other) const { return compare(begin(), end(), other.begin(), other.end()); }

    static int compare(UnsafeConstIterator s1, const UnsafeConstIterator& e1, UnsafeConstIterator s2,
                       const UnsafeConstIterator& e2);

    template<int N>
    inline Chunk chunkFromArray(Offset o, std::array<Byte, N> d) {
        if constexpr ( N <= Chunk::SmallBufferSize )
            return Chunk(o, std::move(d));

        return Chunk(o, Chunk::Vector(d.begin(), d.end()));
    }

    inline Chunk chunkFromArray(Offset o, const char* d, Size n) {
        auto ud = reinterpret_cast<const Byte*>(d);

        if ( n <= Chunk::SmallBufferSize ) {
            std::array<Byte, Chunk::SmallBufferSize> x{};
            std::copy(ud, ud + n.Ref(), x.data());
            return Chunk(o, std::move(x), n); // NOLINT
        }

        return Chunk(o, Chunk::Vector(ud, ud + n.Ref()));
    }

    void appendContent(Content&& ocontent);
    Content deepCopyContent() const;

    Content _content;
    bool _frozen = false;
};

inline std::ostream& operator<<(std::ostream& out, const Stream& x) {
    out << x.data();
    return out;
}

template<>
inline std::string detail::to_string_for_print<Stream>(const Stream& x) {
    return escapeUTF8(x.data(), true);
}

template<>
inline std::string detail::to_string_for_print<stream::View>(const stream::View& x) {
    return escapeUTF8(x.data(), true);
}

namespace detail::adl {
inline auto safe_begin(const Stream& x, adl::tag /*unused*/) { return x.safeBegin(); }
inline auto safe_end(const Stream& x, adl::tag /*unused*/) { return x.safeEnd(); }
inline auto safe_begin(const stream::View& x, adl::tag /*unused*/) { return x.safeBegin(); }
inline auto safe_end(const stream::View& x, adl::tag /*unused*/) { return x.safeEnd(); }
inline std::string to_string(const Stream& x, adl::tag /*unused*/) {
    return fmt("b\"%s\"", escapeUTF8(x.data(), true));
}
inline std::string to_string(const stream::View& x, adl::tag /*unused*/) {
    return fmt("b\"%s\"", escapeUTF8(x.data(), true));
}
} // namespace detail::adl

} // namespace hilti::rt
