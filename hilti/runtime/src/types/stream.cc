// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::stream;
using namespace hilti::rt::stream::detail;

namespace {
// Provide a valid non-null pointer for zero-size data. We initialize it to an
// actual string for easier debugging.
const Byte* EmptyData = reinterpret_cast<const Byte*>("<empty>");
} // namespace

void Chunk::destroy() {
    if ( _allocated > 0 )
        delete[] _data;

    // The default dtr would turn deletion the list behind `_next` into a
    // recursive list traversal. For very long lists this could lead to stack
    // overflows. Traverse the list in a loop instead. This is adapted from
    // https://stackoverflow.com/questions/35535312/stack-overflow-with-unique-ptr-linked-list#answer-35535907.
    for ( auto current = std::move(_next); current; current = std::move(current->_next) )
        ; // Nothing.

    _next = nullptr;
}

Chunk::Chunk(const Offset& offset, const View& d) : _offset(offset), _size(d.size()), _allocated(_size) {
    if ( _size == 0 ) {
        _data = EmptyData;
        return;
    }

    auto data = std::make_unique<Byte[]>(_size);
    d.copyRaw(data.get());
    _data = data.release();
}

Chunk::Chunk(const Offset& offset, std::string_view s) : _offset(offset), _size(s.size()), _allocated(_size) {
    if ( _size == 0 ) {
        _data = EmptyData;
        return;
    }

    auto data = std::make_unique<Byte[]>(_size);
    memcpy(data.get(), s.data(), _size);
    _data = data.release();
}

Chunk::Chunk(const Offset& offset, const Byte* b, size_t size) : _offset(offset), _size(size), _allocated(_size) {
    if ( _size == 0 ) {
        _data = EmptyData;
        return;
    }

    auto data = std::make_unique<Byte[]>(_size);
    memcpy(data.get(), b, _size);
    _data = data.release();
}

void Chain::append(const Byte* data, size_t size) {
    if ( size == 0 )
        return;

    if ( _cached && _cached->allocated() >= size ) {
        // Reuse cached chunk instead of allocating new one.
        memcpy(const_cast<Byte*>(_cached->data()), data, size); // cast is safe because it's allocated
        _cached->_size = size;
        append(std::move(_cached));
    }
    else
        append(std::make_unique<Chunk>(0, data, size));
}

void Chain::append(const Byte* data, size_t size, stream::NonOwning) {
    if ( size == 0 )
        return;

    if ( _cached && ! _cached->isOwning() ) {
        // Reuse cached chunk instead of allocating new one.
        _cached->_data = data;
        _cached->_size = size;
        append(std::move(_cached));
    }
    else
        append(std::make_unique<Chunk>(0, data, size, stream::NonOwning()));
}

void Chain::append(Bytes&& data) {
    if ( data.size() == 0 )
        return;

    if ( _cached && _cached->allocated() >= data.size() ) {
        // Reuse cached chunk instead of allocating new one.
        memcpy(const_cast<Byte*>(_cached->data()), data.data(), data.size()); // cast is safe because it's allocated
        _cached->_size = data.size();
        append(std::move(_cached));
    }
    else
        append(std::make_unique<Chunk>(0, std::move(data).str()));
}

void Chain::append(std::unique_ptr<Chunk> chunk) {
    _ensureValid();
    _ensureMutable();

    if ( chunk->isGap() ) {
        _statistics.num_gap_bytes += chunk->size();
        _statistics.num_gap_chunks++;
    }
    else {
        _statistics.num_data_bytes += chunk->size();
        _statistics.num_data_chunks++;
    }

    if ( _tail ) {
        _tail->setNext(std::move(chunk));
        _tail = _tail->last();
    }
    else {
        assert(! _head);
        chunk->setOffset(_head_offset);
        chunk->setChain(this);
        _head = std::move(chunk);
        _tail = _head->last();
    }
}

void Chain::append(Chain&& other) {
    _ensureValid();
    _ensureMutable();
    other._ensureValid();

    if ( ! other._head )
        return;

    _statistics += other._statistics;

    _tail->setNext(std::move(other._head));
    _tail = other._tail;
    other.reset();
}

void Chain::appendGap(size_t size) {
    if ( size == 0 )
        return;

    append(std::make_unique<Chunk>(0, size));
}

void Chain::trim(const Offset& offset) {
    _ensureValid();

    if ( ! _head || offset < _head->offset() )
        // Noop: chain is empty, or offset is before the head of chain; we do
        // not need to trim anything.
        return;

    // We search the first chunk that's containing the desired position,
    // deleting all the ones we pass on the way. We trim the one that
    // contains the position.
    while ( _head ) {
        if ( offset >= _head->endOffset() ) {
            // Chain should be in order and we progress forward in offset.
            assert(! _head->next() || _head->offset() < _head->next()->offset());

            auto next = std::move(_head->_next);

            if ( ! _head->isGap() &&
                 (! _cached || (! _head->isOwning() || _head->allocated() > _cached->allocated())) ) {
                // Cache chunk for later reuse. If we already have cached one,
                // we prefer the one that's larger. Note that the chunk may be
                // non-owning, we account for that when checking if we can
                // reuse.
                _cached = std::move(_head);
                _cached->detach();
            }

            _head = std::move(next); // deletes chunk if not cached

            if ( ! _head || _head->isLast() )
                _tail = _head.get();
        }

        else if ( _head->inRange(offset) ) {
            // Perform no trimming inside individual chunks.
            break;
        }

        else
            // Other offsets are already rejected before entering loop.
            cannot_be_reached();
    }

    _head_offset = offset;
}

ChainPtr Chain::copy() const {
    _ensureValid();

    auto nchain = make_intrusive<Chain>();

    auto* c = _head.get();
    while ( c ) {
        nchain->append(std::make_unique<Chunk>(*c));
        c = c->next();
    }

    nchain->_statistics = _statistics;
    return nchain;
}

int Chain::numberOfChunks() const {
    int n = 0;
    for ( auto* ch = _head.get(); ch; ch = ch->_next.get() )
        ++n;

    return n;
}

bool View::isComplete() const {
    _ensureValid();

    if ( _begin.isFrozen() )
        return true;

    if ( auto end_offset = endOffset() )
        return *end_offset <= _begin.chain()->endOffset();
    else
        return false;
}

View View::advanceToNextData() const {
    SafeConstIterator i;

    if ( _begin.offset() < _begin.chain()->offset() )
        // We're at a position that has been trimmed already, move to current
        // head of the stream
        i = _begin.chain()->begin();
    else
        // Start search for next data chunk at the next byte. This
        // ensures that we always advance by at least one byte.
        i = _begin + 1;

    const auto* c = i.chunk(); // Pointer to the currently looked at chunk.

    // If the position is already not in a gap we can directly compute a view at it.
    if ( c && ! c->isGap() )
        return View(std::move(i), _end);

    std::optional<Offset> last_end; // Offset of the end of the last seen chunk.

    while ( c ) {
        last_end = c->offset() + c->size();

        // Non-gap found, stop iterating.
        if ( ! c->isGap() )
            break;

        // Work on next chunk.
        c = c->next();
    }

    // Iterator to zero point in original stream. All offsets are relative to this.
    const auto zero = _begin - _begin.offset();

    // If we have found a non-gap chunk its offset points to the next data.
    if ( c )
        return View(zero + c->offset(), _end);

    // If we have seen a previous chunk, return a View starting after its end.
    if ( last_end )
        return View(zero + *last_end, _end);

    // If we have not found a next non-gap chunk simply return a view at the next
    // byte. Since this is a gap chunk this can cause recovery in the caller.
    return advance(1U);
}

UnsafeConstIterator View::find(Byte b, UnsafeConstIterator n) const {
    if ( ! n )
        n = unsafeBegin();

    for ( auto i = n; i != unsafeEnd(); ++i ) {
        if ( *i == b )
            return i;
    }

    return unsafeEnd();
}

Tuple<bool, UnsafeConstIterator> View::find(const View& v, UnsafeConstIterator n) const {
    if ( ! n )
        n = UnsafeConstIterator(_begin);

    if ( v.isEmpty() )
        return tuple::make(true, n);

    auto first = *v.unsafeBegin();

    for ( auto i = n; true; ++i ) {
        if ( i == unsafeEnd() )
            return tuple::make(false, i);

        if ( *i != first )
            continue;

        auto x = i;
        auto y = v.unsafeBegin();

        for ( ;; ) {
            if ( x == unsafeEnd() )
                return tuple::make(false, i);

            if ( *x++ != *y++ )
                break;

            if ( y == v.unsafeEnd() )
                return tuple::make(true, i);
        }
    }
}

Tuple<bool, UnsafeConstIterator> View::_findForward(const Bytes& v, UnsafeConstIterator n) const {
    if ( ! n )
        n = UnsafeConstIterator(_begin);

    if ( v.isEmpty() )
        return tuple::make(true, n);

    auto first = *v.unsafeBegin();

    for ( auto i = n; true; ++i ) {
        if ( i == unsafeEnd() )
            return tuple::make(false, i);

        if ( *i != first )
            continue;

        auto x = i;
        auto y = v.unsafeBegin();

        for ( ;; ) {
            if ( x == unsafeEnd() )
                return tuple::make(false, i);

            if ( *x++ != *y++ )
                break;

            if ( y == v.unsafeEnd() )
                return tuple::make(true, i);
        }
    }
}

Tuple<bool, UnsafeConstIterator> View::_findBackward(const Bytes& needle, UnsafeConstIterator i) const {
    // We can assume that "i" is inside the view.

    // An empty pattern always matches at the current position.
    if ( needle.isEmpty() )
        return tuple::make(true, i);

    if ( ! i )
        i = unsafeEnd();

    // If "i" is pointing beyond the currently available bytes, we abort because
    // we'll have a gap that we don't want to search across. (Note that size()
    // does the right thing here by returning the number of *available* bytes.)
    if ( i.offset() > offset() + size() )
        throw InvalidIterator("iterator pointing beyond available data");

    if ( i.offset() < offset() )
        throw InvalidIterator("iterator preceding available data");

    // If we don't have enough bytes available to fit the pattern in, we
    // can stop right away.
    if ( needle.size() > (i.offset() - offset()) )
        return tuple::make(false, UnsafeConstIterator());

    i -= (needle.size() - 1).Ref(); // this is safe now, get us 1st position where initial character may match

    auto first = *needle.unsafeBegin();

    // The following is not the most efficient way to search backwards, but
    // it'll do for now.
    for ( auto j = i; true; --j ) {
        if ( *j == first ) {
            auto x = j;
            auto y = needle.unsafeBegin();

            for ( ;; ) {
                if ( *x++ != *y++ )
                    break;

                if ( y == needle.unsafeEnd() )
                    return tuple::make(true, j);
            }
        }

        if ( j == unsafeBegin() )
            return tuple::make(false, j);
    }
}

void View::_force_vtable() {}

bool View::startsWith(const Bytes& b) const {
    _ensureValid();
    auto s1 = unsafeBegin();
    auto e1 = unsafeEnd();
    auto s2 = b.unsafeBegin();
    auto e2 = b.unsafeEnd();

    // If the iterator has no data in it, we cannot dereference it.
    if ( isEmpty() )
        return b.isEmpty();

    while ( s1 != e1 && s2 != e2 ) {
        if ( *s1++ != *s2++ )
            return false;
    }

    return s2 == e2;
}

void View::copyRaw(Byte* dst) const {
    for ( auto i = unsafeBegin(); i != unsafeEnd(); ++i )
        *dst++ = *i;
}

std::optional<View::Block> View::firstBlock() const {
    _ensureValid();

    auto begin = unsafeBegin();
    if ( begin == unsafeEnd() || ! begin.chunk() )
        return {};

    const auto* chain = begin.chain();
    assert(chain);

    const auto* chunk = chain->findChunk(begin.offset(), begin.chunk());
    if ( ! chunk )
        throw InvalidIterator("stream iterator outside of valid range");

    const auto* start = chunk->data() + (begin.offset() - chunk->offset()).Ref();
    bool is_last = (chunk->isLast() || (_end && _end->offset() <= chunk->endOffset()));

    Size size;

    if ( _end && is_last ) {
        auto offset_end = std::max(std::min(_end->offset(), chain->endOffset()), begin.offset());
        size = (offset_end - begin.offset());
    }
    else
        size = chunk->endData() - start;

    return View::Block{.start = start,
                       .size = size,
                       .offset = begin.offset(),
                       .is_first = true,
                       .is_last = is_last,
                       ._block = is_last ? nullptr : chunk->next()};
}

std::optional<View::Block> View::nextBlock(std::optional<Block> current) const {
    _ensureValid();

    if ( ! (current && current->_block) )
        return {};

    const auto* chunk = current->_block;

    const auto* start = chunk->data();
    bool is_last = (chunk->isLast() || (_end && _end->offset() <= chunk->endOffset()));

    Size size;

    if ( _end && is_last ) {
        auto offset_end = std::max(std::min(_end->offset(), _begin.chain()->endOffset()), chunk->offset());
        size = offset_end - chunk->offset();
    }
    else
        size = chunk->size();

    return View::Block{.start = start,
                       .size = size,
                       .offset = chunk->offset(),
                       .is_first = false,
                       .is_last = is_last,
                       ._block = is_last ? nullptr : chunk->next()};
}

Stream::Stream(Bytes d) : Stream(Chunk(0, std::move(d).str())) {}

void Stream::append(const Bytes& data) { _chain->append(reinterpret_cast<const Byte*>(data.data()), data.size()); }

void Stream::append(Bytes&& data) { _chain->append(std::move(data)); }

void Stream::append(const char* data, size_t len) {
    if ( data )
        _chain->append(reinterpret_cast<const Byte*>(data), len);
    else
        _chain->appendGap(len);
}

void Stream::append(const char* data, size_t len, NonOwning) {
    if ( len == 0 )
        return;

    if ( data )
        _chain->append(reinterpret_cast<const Byte*>(data), len, stream::NonOwning());
    else
        _chain->appendGap(len);
}

std::string stream::View::dataForPrint() const {
    std::string data;

    const auto begin = unsafeBegin();
    const auto end = unsafeEnd();

    const auto start = begin.offset();
    const auto stop = end.offset();

    const auto* c = begin.chunk();
    while ( c && c->offset() < stop ) {
        if ( c->isGap() )
            data.append("<gap>");

        else {
            const auto* cstart = c->data();
            auto csize = c->size();

            if ( c->inRange(start) ) {
                cstart = cstart + (start - c->offset()).Ref();
                csize = csize - (start - c->offset()).Ref();
            }

            if ( c->inRange(start) && c->inRange(stop) )
                csize = stop - start;
            else if ( c->inRange(stop) )
                csize = stop - c->offset();

            data.append(reinterpret_cast<const char*>(cstart), csize);
        }

        c = c->next();
    }

    return data;
}

bool stream::View::operator==(const Stream& other) const { return *this == other.view(); }

bool stream::View::operator==(const View& other) const {
    if ( size() != other.size() )
        return false;

    auto i = unsafeBegin();
    auto j = other.unsafeBegin();

    while ( i != unsafeEnd() ) {
        if ( ! i.chunk() || ! j.chunk() )
            return (i.chunk() == j.chunk() && i.offset() == j.offset()); // same out-of-bounds iterators

        if ( i.chunk()->isGap() != j.chunk()->isGap() )
            return false;

        if ( ! i.chunk()->isGap() && *i != *j )
            return false;

        ++i;
        ++j;
    }

    return true;
}

bool stream::View::operator==(const Bytes& other) const {
    if ( size() != other.size() )
        return false;

    auto i = unsafeBegin();
    auto j = other.unsafeBegin();

    while ( i != unsafeEnd() ) {
        if ( ! i.chunk() ) // out-of-bounds, cannot match
            return false;

        if ( *i++ != *j++ )
            return false;
    }

    return true;
}

std::string hilti::rt::detail::adl::to_string(const stream::SafeConstIterator& x, adl::tag /*unused*/) {
    auto str = [](const auto& x) {
        auto y = x + 10;
        auto v = stream::View(x, y);
        if ( y.isEnd() )
            return fmt("%s", hilti::rt::to_string(v));

        return fmt("%s...", hilti::rt::to_string(v));
    };

    if ( x.isExpired() )
        return "<expired>";

    if ( x.isUnset() )
        return "<uninitialized>";

    return fmt("<offset=%" PRIu64 " data=%s>", x.offset(), str(x));
}

void SafeConstIterator::debugPrint(std::ostream& out) const {
    int chunk = 0;

    const auto* c = _chain->head();
    while ( c ) {
        if ( c == _chunk )
            break;

        chunk++;
        c = c->next();
    }

    if ( ! c )
        // Can happen if trimmed off.
        chunk = -1;

    out << fmt("iterator %p: chain=%p chunk=#%d/%p offset=%llu is_end=%d\n", this, _chain.get(), chunk, c, _offset,
               static_cast<int>(isEnd()));
}

std::string hilti::rt::detail::adl::to_string(const UnsafeConstIterator& x, adl::tag /*unused*/) {
    auto str = [](auto x) {
        auto y = x + 10;
        auto v = stream::View(SafeConstIterator(x), SafeConstIterator(y));
        if ( y.isEnd() )
            return fmt("%s", hilti::rt::to_string(v));

        return fmt("%s...", hilti::rt::to_string(v));
    };

    if ( x.isExpired() )
        return "<expired>";

    if ( x.isUnset() )
        return "<uninitialized>";

    return fmt("<offset=%" PRIu64 " data=%s>", x.offset(), str(x));
}

void UnsafeConstIterator::debugPrint(std::ostream& out) const {
    int chunk = 0;

    const auto* c = _chain->head();
    while ( c ) {
        if ( c == _chunk )
            break;

        chunk++;
        c = c->next();
    }

    if ( ! c )
        // Can happen if trimmed off.
        chunk = -1;

    out << fmt("unsafe iterator %p: parent=%p chunk=#%d/%p offset=%llu is_end=%d\n", this, _chain, chunk, c, _offset,
               static_cast<int>(isEnd()));
}

void View::debugPrint(std::ostream& out) const {
    out << "[begin] ";
    _begin.debugPrint(out);

    out << "[end]   ";

    if ( _end )
        _end->debugPrint(out);
    else
        out << "<not set>\n";

    out << "[data]" << '\n';
    Stream::debugPrint(out, _begin.chain());
}

void Stream::debugPrint(std::ostream& out, const stream::detail::Chain* chain) {
    out << fmt("chain %p", chain) << '\n';
    int i = 0;
    const auto* c = chain->head();
    while ( c ) {
        out << fmt("  #%d/%p: ", i++, c);
        c->debugPrint(out);
        c = c->next();
    }
}

void Stream::debugPrint(std::ostream& out) const { debugPrint(out, _chain.get()); }

void Chunk::debugPrint(std::ostream& out) const {
    auto x = std::string(reinterpret_cast<const char*>(data()), size());
    x = escapeBytes(x);
    out << fmt("offset %lu  data=|%s| (%s)", _offset, x, (isOwning() ? "owning" : "non-owning")) << '\n';
}
