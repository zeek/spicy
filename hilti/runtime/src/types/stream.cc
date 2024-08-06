// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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

    auto c = _head.get();
    while ( c ) {
        nchain->append(std::make_unique<Chunk>(*c));
        c = c->next();
    }

    nchain->_statistics = _statistics;
    return nchain;
}

int Chain::numberOfChunks() const {
    int n = 0;
    for ( auto ch = _head.get(); ch; ch = ch->_next.get() )
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
    // Start search for next data chunk at the next byte. This
    // ensures that we always advance by at least one byte.
    auto i = _begin + 1;

    auto* c = i.chunk(); // Pointer to the currently looked at chunk.

    // If the position is already not in a gap we can directly compute a view at it.
    if ( c && ! c->isGap() )
        return View(i, _end);

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

std::tuple<bool, UnsafeConstIterator> View::find(const View& v, UnsafeConstIterator n) const {
    if ( ! n )
        n = UnsafeConstIterator(_begin);

    if ( v.isEmpty() )
        return std::make_tuple(true, n);

    auto first = *v.begin();

    for ( auto i = n; true; ++i ) {
        if ( i == unsafeEnd() )
            return std::make_tuple(false, i);

        if ( *i != first )
            continue;

        auto x = i;
        auto y = v.unsafeBegin();

        for ( ;; ) {
            if ( x == unsafeEnd() )
                return std::make_tuple(false, i);

            if ( *x++ != *y++ )
                break;

            if ( y == v.unsafeEnd() )
                return std::make_tuple(true, i);
        }
    }
}

std::tuple<bool, UnsafeConstIterator> View::_findForward(const Bytes& v, UnsafeConstIterator n) const {
    if ( ! n )
        n = UnsafeConstIterator(_begin);

    if ( v.isEmpty() )
        return std::make_tuple(true, n);

    auto first = *v.begin();

    for ( auto i = n; true; ++i ) {
        if ( i == unsafeEnd() )
            return std::make_tuple(false, i);

        if ( *i != first )
            continue;

        auto x = i;
        auto y = v.begin();

        for ( ;; ) {
            if ( x == unsafeEnd() )
                return std::make_tuple(false, i);

            if ( *x++ != *y++ )
                break;

            if ( y == v.end() )
                return std::make_tuple(true, i);
        }
    }
}

std::tuple<bool, UnsafeConstIterator> View::_findBackward(const Bytes& needle, UnsafeConstIterator i) const {
    // We can assume that "i" is inside the view.

    // An empty pattern always matches at the current position.
    if ( needle.isEmpty() )
        return std::make_tuple(true, i);

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
        return std::make_tuple(false, UnsafeConstIterator());

    i -= (needle.size() - 1).Ref(); // this is safe now, get us 1st position where initial character may match

    auto first = *needle.begin();

    // The following is not the most efficient way to search backwards, but
    // it'll do for now.
    for ( auto j = i; true; --j ) {
        if ( *j == first ) {
            auto x = j;
            auto y = needle.begin();

            for ( ;; ) {
                if ( *x++ != *y++ )
                    break;

                if ( y == needle.end() )
                    return std::make_tuple(true, j);
            }
        }

        if ( j == unsafeBegin() )
            return std::make_tuple(false, j);
    }
}

void View::_force_vtable() {}

bool View::startsWith(const Bytes& b) const {
    _ensureValid();
    auto s1 = unsafeBegin();
    auto e1 = unsafeEnd();
    auto s2 = b.begin();
    auto e2 = b.end();

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

    auto chunk = chain->findChunk(begin.offset(), begin.chunk());
    if ( ! chunk )
        throw InvalidIterator("stream iterator outside of valid range");

    auto start = chunk->data() + (begin.offset() - chunk->offset()).Ref();
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

    auto chunk = current->_block;

    auto start = chunk->data();
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

    auto* c = begin.chunk();
    while ( c && c->offset() < stop ) {
        if ( c->isGap() )
            data.append("<gap>");

        else {
            auto cstart = c->data();
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
    auto j = other.begin();

    while ( i != unsafeEnd() ) {
        if ( *i++ != *j++ )
            return false;
    }

    return true;
}

std::string hilti::rt::detail::adl::to_string(const stream::SafeConstIterator& x, adl::tag /*unused*/) {
    auto str = [](auto x) {
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

    auto c = _chain->head();
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

    auto c = _chain->head();
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
    auto c = chain->head();
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

hilti::rt::stream::detail::Chunk& hilti::rt::stream::detail::Chunk::operator=(const Chunk& other) {
    if ( &other == this )
        return *this;

    destroy();

    _offset = other._offset;
    _size = other._size;
    _data = other._data;
    _allocated = 0;
    _chain = other._chain;
    _next = nullptr;

    if ( other.isOwning() )
        makeOwning();

    return *this;
}

hilti::rt::stream::detail::Chunk& hilti::rt::stream::detail::Chunk::operator=(Chunk&& other) noexcept {
    if ( _allocated > 0 )
        delete[] _data;

    _offset = other._offset;
    _size = other._size;
    _allocated = other._allocated;
    _data = other._data;
    _chain = other._chain;
    _next = std::move(other._next);

    other._size = 0;
    other._allocated = 0;
    other._data = nullptr;

    return *this;
}
hilti::rt::stream::detail::Chunk::Chunk(const Offset& o, const Byte* b, size_t size, NonOwning)
    : _offset(o), _size(size), _data(b) {}
hilti::rt::stream::detail::Chunk::Chunk(const Offset& o, size_t len) : _offset(o), _size(len) { assert(_size > 0); }
hilti::rt::stream::detail::Chunk::Chunk(const Chunk& other)
    : _offset(other._offset), _size(other._size), _data(other._data), _chain(other._chain), _next(nullptr) {
    if ( other.isOwning() )
        makeOwning();
}
hilti::rt::stream::detail::Chunk::Chunk(Chunk&& other) noexcept
    : _offset(other._offset),
      _size(other._size),
      _allocated(other._allocated),
      _data(other._data),
      _chain(other._chain),
      _next(std::move(other._next)) {
    other._size = 0;
    other._allocated = 0;
    other._data = nullptr;
}
hilti::rt::stream::detail::Chunk::~Chunk() { destroy(); }
hilti::rt::stream::Offset hilti::rt::stream::detail::Chunk::offset() const { return _offset; }
hilti::rt::stream::Offset hilti::rt::stream::detail::Chunk::endOffset() const { return _offset + size(); }
bool hilti::rt::stream::detail::Chunk::isGap() const { return _data == nullptr; };
bool hilti::rt::stream::detail::Chunk::isOwning() const { return _allocated > 0; }
bool hilti::rt::stream::detail::Chunk::inRange(const Offset& offset) const {
    return offset >= _offset && offset < endOffset();
}
const hilti::rt::stream::Byte* hilti::rt::stream::detail::Chunk::data() const {
    if ( isGap() )
        throw MissingData("data is missing");

    return _data;
}
const hilti::rt::stream::Byte* hilti::rt::stream::detail::Chunk::data(const Offset& offset) const {
    assert(inRange(offset));
    return data() + (offset - _offset).Ref();
}
const hilti::rt::stream::Byte* hilti::rt::stream::detail::Chunk::endData() const {
    if ( isGap() )
        throw MissingData("data is missing");

    return data() + _size;
}
hilti::rt::stream::Size hilti::rt::stream::detail::Chunk::size() const { return _size; }
hilti::rt::stream::Size hilti::rt::stream::detail::Chunk::allocated() const { return _allocated; }
bool hilti::rt::stream::detail::Chunk::isLast() const { return ! _next; }
const hilti::rt::stream::detail::Chunk* hilti::rt::stream::detail::Chunk::next() const { return _next.get(); }
const Chunk* hilti::rt::stream::detail::Chunk::last() const {
    const Chunk* i = this;
    while ( i && i->_next )
        i = i->_next.get();
    return i;
}
Chunk* hilti::rt::stream::detail::Chunk::last() {
    Chunk* i = this;
    while ( i && i->_next )
        i = i->_next.get();
    return i;
}
void hilti::rt::stream::detail::Chunk::makeOwning() {
    if ( _size == 0 || _allocated > 0 || ! _data )
        return;

    auto data = std::make_unique<Byte[]>(_size);
    memcpy(data.get(), _data, _size);
    _allocated = _size;
    _data = data.release();
}
void hilti::rt::stream::detail::Chunk::setOffset(Offset o) {
    auto c = this;
    while ( c ) {
        c->_offset = o;
        o += c->size();
        c = c->next();
    }
}
void hilti::rt::stream::detail::Chunk::setChain(const Chain* chain) {
    auto x = this;
    while ( x ) {
        x->_chain = chain;
        x = x->_next.get();
    }
}
hilti::rt::stream::detail::Chunk* hilti::rt::stream::detail::Chunk::next() { return _next.get(); }
void hilti::rt::stream::detail::Chunk::setNext(std::unique_ptr<Chunk> next) {
    assert(_chain);

    makeOwning();
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
void hilti::rt::stream::detail::Chunk::detach() {
    _offset = 0;
    _chain = nullptr;
    _next = nullptr;
}
hilti::rt::stream::detail::Chunk::Chunk() {}
hilti::rt::stream::detail::Chain::Chain() {}
hilti::rt::stream::detail::Chain::Chain(std::unique_ptr<Chunk> head) : _head(std::move(head)), _tail(_head->last()) {
    _head->setChain(this);

    if ( auto size = _head->size() ) {
        if ( _head->isGap() ) {
            _statistics.num_gap_bytes = _head->size();
            _statistics.num_gap_chunks = 1;
        }
        else {
            _statistics.num_data_bytes = _head->size();
            _statistics.num_data_chunks = 1;
        }
    }
}
const hilti::rt::stream::detail::Chunk* hilti::rt::stream::detail::Chain::head() const { return _head.get(); }
const hilti::rt::stream::detail::Chunk* hilti::rt::stream::detail::Chain::tail() const { return _tail; }
hilti::rt::stream::detail::Chunk* hilti::rt::stream::detail::Chain::tail() { return _tail; }
hilti::rt::stream::detail::Chain::Size hilti::rt::stream::detail::Chain::size() const {
    return (endOffset() - offset()).Ref();
}
bool hilti::rt::stream::detail::Chain::isFrozen() const { return _state == State::Frozen; }
bool hilti::rt::stream::detail::Chain::isValid() const { return _state != State::Invalid; }
bool hilti::rt::stream::detail::Chain::inRange(const Offset& o) const { return o >= offset() && o < endOffset(); }
hilti::rt::stream::Offset hilti::rt::stream::detail::Chain::offset() const { return _head_offset; }
hilti::rt::stream::Offset hilti::rt::stream::detail::Chain::endOffset() const {
    return _tail ? _tail->endOffset() : _head_offset;
}
void hilti::rt::stream::detail::Chain::invalidate() {
    _state = State::Invalid;
    _head.reset();
    _head_offset = 0;
    _tail = nullptr;
    _statistics = {};
}
void hilti::rt::stream::detail::Chain::reset() {
    _state = State::Mutable;
    _head.reset();
    _head_offset = 0;
    _tail = nullptr;
    _statistics = {};
}
void hilti::rt::stream::detail::Chain::freeze() {
    if ( isValid() )
        _state = State::Frozen;
}
void hilti::rt::stream::detail::Chain::unfreeze() {
    if ( isValid() )
        _state = State::Mutable;
}
const Statistics& hilti::rt::stream::detail::Chain::statistics() const { return _statistics; }
void hilti::rt::stream::detail::Chain::_ensureValid() const {
    if ( ! isValid() )
        throw InvalidIterator("stream object no longer available");
}
void hilti::rt::stream::detail::Chain::_ensureMutable() const {
    if ( isFrozen() )
        throw Frozen("stream object can no longer be modified");
}
hilti::rt::stream::SafeConstIterator::Offset hilti::rt::stream::SafeConstIterator::offset() const { return _offset; }
bool hilti::rt::stream::SafeConstIterator::isFrozen() const { return ! _chain || _chain->isFrozen(); }
hilti::rt::stream::SafeConstIterator& hilti::rt::stream::SafeConstIterator::operator++() {
    _increment(1);
    return *this;
}
hilti::rt::stream::SafeConstIterator hilti::rt::stream::SafeConstIterator::operator++(int) {
    auto x = *this;
    _increment(1);
    return x;
}
hilti::rt::stream::SafeConstIterator& hilti::rt::stream::SafeConstIterator::operator+=(
    const integer::safe<uint64_t>& i) {
    _increment(i);
    return *this;
}
hilti::rt::stream::SafeConstIterator& hilti::rt::stream::SafeConstIterator::operator--() {
    _decrement(1);
    return *this;
}
hilti::rt::stream::SafeConstIterator hilti::rt::stream::SafeConstIterator::operator--(int) {
    auto x = *this;
    _decrement(1);
    return x;
}
hilti::rt::stream::SafeConstIterator& hilti::rt::stream::SafeConstIterator::operator-=(
    const integer::safe<uint64_t>& i) {
    _decrement(i);
    return *this;
}
hilti::rt::stream::SafeConstIterator::Byte hilti::rt::stream::SafeConstIterator::operator*() const {
    return _dereference();
}
hilti::rt::stream::SafeConstIterator hilti::rt::stream::SafeConstIterator::operator+(
    const integer::safe<uint64_t>& i) const {
    auto x = *this;
    x._increment(i);
    return x;
}
hilti::rt::stream::SafeConstIterator hilti::rt::stream::SafeConstIterator::operator-(
    const integer::safe<uint64_t>& i) const {
    auto x = *this;
    x._decrement(i);
    return x;
}
hilti::rt::integer::safe<int64_t> hilti::rt::stream::SafeConstIterator::operator-(
    const SafeConstIterator& other) const {
    _ensureSameChain(other);
    return static_cast<int64_t>(_offset) - static_cast<int64_t>(other._offset);
}
bool hilti::rt::stream::SafeConstIterator::operator==(const SafeConstIterator& other) const {
    _ensureSameChain(other);
    return (_offset == other._offset) || (isEnd() && other.isEnd());
}
bool hilti::rt::stream::SafeConstIterator::operator!=(const SafeConstIterator& other) const {
    _ensureSameChain(other);
    return ! (*this == other);
}
bool hilti::rt::stream::SafeConstIterator::operator<(const SafeConstIterator& other) const {
    _ensureSameChain(other);
    return offset() < other.offset();
}
bool hilti::rt::stream::SafeConstIterator::operator<=(const SafeConstIterator& other) const {
    _ensureSameChain(other);
    return offset() <= other.offset();
}
bool hilti::rt::stream::SafeConstIterator::operator>(const SafeConstIterator& other) const {
    _ensureSameChain(other);
    return offset() > other.offset();
}
bool hilti::rt::stream::SafeConstIterator::operator>=(const SafeConstIterator& other) const {
    _ensureSameChain(other);
    return offset() >= other.offset();
}
hilti::rt::stream::SafeConstIterator::operator bool() const { return ! isUnset(); }
std::ostream& hilti::rt::stream::SafeConstIterator::operator<<(std::ostream& out) const {
    out << to_string(*this);
    return out;
}
bool hilti::rt::stream::SafeConstIterator::isUnset() const { return ! _chain; }
bool hilti::rt::stream::SafeConstIterator::isExpired() const {
    if ( ! _chain )
        return false;

    return ! _chain->isValid();
}
bool hilti::rt::stream::SafeConstIterator::isValid() const { return ! isUnset() && ! isExpired(); }
bool hilti::rt::stream::SafeConstIterator::isEnd() const {
    if ( ! _chain )
        return true;

    _ensureValidChain();
    return _offset >= _chain->endOffset();
}
const hilti::rt::stream::SafeConstIterator::Chunk* hilti::rt::stream::SafeConstIterator::chunk() const {
    return _chain && _chain->isValid() && _chain->inRange(_offset) ? _chunk : nullptr;
}
const hilti::rt::stream::SafeConstIterator::Chain* hilti::rt::stream::SafeConstIterator::chain() const {
    return _chain.get();
}
hilti::rt::stream::SafeConstIterator::SafeConstIterator(ChainPtr chain, const Offset& offset, const Chunk* chunk)
    : _chain(std::move(chain)), _offset(offset), _chunk(chunk) {
    assert(! isUnset());
}
void hilti::rt::stream::SafeConstIterator::_ensureValidChain() const {
    // This must have been checked at this point already.
    assert(_chain);

    if ( ! _chain->isValid() )
        throw InvalidIterator("stream object no longer available");
}
void hilti::rt::stream::SafeConstIterator::_ensureSameChain(const SafeConstIterator& other) const {
    if ( ! (_chain && other._chain) )
        // One is the default constructed end iterator; that's ok.
        return;

    if ( ! other.isValid() )
        throw InvalidIterator("stream object no longer available");

    if ( _chain != other._chain )
        throw InvalidIterator("incompatible iterators");
}
void hilti::rt::stream::SafeConstIterator::_increment(const integer::safe<uint64_t>& n) {
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
void hilti::rt::stream::SafeConstIterator::_decrement(const integer::safe<uint64_t>& n) {
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
hilti::rt::stream::SafeConstIterator::Byte hilti::rt::stream::SafeConstIterator::_dereference() const {
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
std::ostream& hilti::rt::stream::operator<<(std::ostream& out, const SafeConstIterator& x) {
    out << to_string(x);
    return out;
}
hilti::rt::stream::detail::UnsafeConstIterator::Offset hilti::rt::stream::detail::UnsafeConstIterator::offset() const {
    return _offset;
}
bool hilti::rt::stream::detail::UnsafeConstIterator::isFrozen() const { return ! _chain || _chain->isFrozen(); }
hilti::rt::stream::detail::UnsafeConstIterator& hilti::rt::stream::detail::UnsafeConstIterator::operator++() {
    _increment(1);
    return *this;
}
hilti::rt::stream::detail::UnsafeConstIterator hilti::rt::stream::detail::UnsafeConstIterator::operator++(int) {
    auto x = *this;
    _increment(1);
    return x;
}
hilti::rt::stream::detail::UnsafeConstIterator& hilti::rt::stream::detail::UnsafeConstIterator::operator--() {
    _decrement(1);
    return *this;
}
hilti::rt::stream::detail::UnsafeConstIterator hilti::rt::stream::detail::UnsafeConstIterator::operator--(int) {
    auto x = *this;
    _decrement(1);
    return x;
}
hilti::rt::stream::detail::UnsafeConstIterator& hilti::rt::stream::detail::UnsafeConstIterator::operator-=(
    const integer::safe<uint64_t>& i) {
    _decrement(i);
    return *this;
}
hilti::rt::stream::detail::UnsafeConstIterator::Byte hilti::rt::stream::detail::UnsafeConstIterator::operator*() const {
    return _dereference();
}
hilti::rt::stream::detail::UnsafeConstIterator hilti::rt::stream::detail::UnsafeConstIterator::operator+(
    const integer::safe<uint64_t>& i) const {
    auto x = *this;
    x._increment(i);
    return x;
}
hilti::rt::stream::detail::UnsafeConstIterator hilti::rt::stream::detail::UnsafeConstIterator::operator-(
    const integer::safe<uint64_t>& i) const {
    auto x = *this;
    x._decrement(i);
    return x;
}
hilti::rt::integer::safe<int64_t> hilti::rt::stream::detail::UnsafeConstIterator::operator-(
    const UnsafeConstIterator& other) const {
    return static_cast<int64_t>(_offset) - static_cast<int64_t>(other._offset);
}
bool hilti::rt::stream::detail::UnsafeConstIterator::operator==(const UnsafeConstIterator& other) const {
    return (_offset == other._offset) || (isEnd() && other.isEnd());
}
bool hilti::rt::stream::detail::UnsafeConstIterator::operator!=(const UnsafeConstIterator& other) const {
    return ! (*this == other);
}
bool hilti::rt::stream::detail::UnsafeConstIterator::operator<(const UnsafeConstIterator& other) const {
    return offset() < other.offset();
}
bool hilti::rt::stream::detail::UnsafeConstIterator::operator<=(const UnsafeConstIterator& other) const {
    return offset() <= other.offset();
}
bool hilti::rt::stream::detail::UnsafeConstIterator::operator>(const UnsafeConstIterator& other) const {
    return offset() > other.offset();
}
bool hilti::rt::stream::detail::UnsafeConstIterator::operator>=(const UnsafeConstIterator& other) const {
    return offset() >= other.offset();
}
hilti::rt::stream::detail::UnsafeConstIterator::operator bool() const { return ! isUnset(); }
bool hilti::rt::stream::detail::UnsafeConstIterator::isUnset() const { return ! _chain; }
bool hilti::rt::stream::detail::UnsafeConstIterator::isExpired() const {
    if ( ! _chain )
        return false;

    return ! _chain->isValid();
}
bool hilti::rt::stream::detail::UnsafeConstIterator::isValid() const { return ! isUnset() && ! isExpired(); }
bool hilti::rt::stream::detail::UnsafeConstIterator::isEnd() const {
    if ( ! _chain )
        return true;

    return _offset >= _chain->endOffset();
}
std::ostream& hilti::rt::stream::detail::UnsafeConstIterator::operator<<(std::ostream& out) const {
    out << to_string(*this);
    return out;
}
const hilti::rt::stream::detail::UnsafeConstIterator::Chunk* hilti::rt::stream::detail::UnsafeConstIterator::chunk()
    const {
    return _chunk;
}
const hilti::rt::stream::detail::UnsafeConstIterator::Chain* hilti::rt::stream::detail::UnsafeConstIterator::chain()
    const {
    return _chain;
}
hilti::rt::stream::detail::UnsafeConstIterator::UnsafeConstIterator(const ChainPtr& chain, const Offset& offset,
                                                                    const Chunk* chunk)
    : _chain(chain.get()), _offset(offset), _chunk(chunk) {
    assert(! isUnset());
}
hilti::rt::stream::detail::UnsafeConstIterator::UnsafeConstIterator(const Chain* chain, const Offset& offset,
                                                                    const Chunk* chunk)
    : _chain(chain), _offset(offset), _chunk(chunk) {
    assert(! isUnset());
}
void hilti::rt::stream::detail::UnsafeConstIterator::_increment(const integer::safe<uint64_t>& n) {
    if ( n == 0 )
        return;

    _offset += n;

    if ( _chunk && _offset < _chunk->endOffset() )
        return; // fast-path, chunk still valid

    _chunk = _chain->findChunk(_offset, _chunk);
}
void hilti::rt::stream::detail::UnsafeConstIterator::_decrement(const integer::safe<uint64_t>& n) {
    if ( n == 0 )
        return;

    _offset -= n;

    if ( _chunk && _offset > _chunk->offset() )
        return; // fast-path, chunk still valid

    _chunk = _chain->findChunk(_offset, _chunk);
}
hilti::rt::stream::detail::UnsafeConstIterator::Byte hilti::rt::stream::detail::UnsafeConstIterator::_dereference()
    const {
    assert(_chunk);

    auto* byte = _chunk->data(_offset);

    if ( ! byte )
        throw MissingData("data is missing");

    return *byte;
}
hilti::rt::stream::detail::UnsafeConstIterator::UnsafeConstIterator(const SafeConstIterator& i)
    : _chain(i.chain()), _offset(i.offset()), _chunk(i.chain() ? i.chain()->findChunk(_offset, i.chunk()) : nullptr) {}
std::ostream& hilti::rt::stream::detail::operator<<(std::ostream& out, const UnsafeConstIterator& x) {
    out << to_string(x);
    return out;
}
hilti::rt::stream::detail::Chain::SafeConstIterator hilti::rt::stream::detail::Chain::begin() const {
    _ensureValid();
    return {ChainPtr(intrusive_ptr::NewRef(), const_cast<Chain*>(this)), offset(), _head.get()};
}
hilti::rt::stream::detail::Chain::SafeConstIterator hilti::rt::stream::detail::Chain::end() const {
    _ensureValid();
    return {ChainPtr(intrusive_ptr::NewRef(), const_cast<Chain*>(this)), endOffset(), _tail};
}
hilti::rt::stream::detail::Chain::SafeConstIterator hilti::rt::stream::detail::Chain::at(const Offset& offset) const {
    return {ChainPtr(intrusive_ptr::NewRef(), const_cast<Chain*>(this)), offset, findChunk(offset)};
}
hilti::rt::stream::detail::Chain::UnsafeConstIterator hilti::rt::stream::detail::Chain::unsafeBegin() const {
    _ensureValid();
    return {ChainPtr(intrusive_ptr::NewRef(), const_cast<Chain*>(this)), offset(), _tail};
}
hilti::rt::stream::detail::Chain::UnsafeConstIterator hilti::rt::stream::detail::Chain::unsafeEnd() const {
    _ensureValid();
    return {ChainPtr(intrusive_ptr::NewRef(), const_cast<Chain*>(this)), endOffset(), _tail};
}
void hilti::rt::stream::detail::Chain::trim(const SafeConstIterator& i) {
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
void hilti::rt::stream::detail::Chain::trim(const UnsafeConstIterator& i) { trim(i.offset()); }
const hilti::rt::stream::Byte* hilti::rt::stream::detail::Chain::data(const Offset& offset, Chunk* hint_prev) const {
    auto c = findChunk(offset, hint_prev);
    if ( ! c )
        throw InvalidIterator("stream iterator outside of valid range");

    return c->data(offset);
}
hilti::rt::stream::detail::Chunk* hilti::rt::stream::detail::Chain::findChunk(const Offset& offset, Chunk* hint_prev) {
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
const hilti::rt::stream::detail::Chunk* hilti::rt::stream::detail::Chain::findChunk(const Offset& offset,
                                                                                    const Chunk* hint_prev) const {
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

hilti::rt::stream::SafeConstIterator::SafeConstIterator(const UnsafeConstIterator& i)
    : _chain(detail::ChainPtr(intrusive_ptr::NewRef(), const_cast<Chain*>(i._chain))),
      _offset(i._offset),
      _chunk(i._chunk) {}
bool hilti::rt::stream::View::operator!=(const View& other) const { return ! (*this == other); }
bool hilti::rt::stream::View::operator!=(const Stream& other) const { return ! (*this == other); }
bool hilti::rt::stream::View::operator!=(const Bytes& other) const { return ! (*this == other); }
hilti::rt::stream::SafeConstIterator hilti::rt::stream::View::cend() const { return end(); }
hilti::rt::stream::SafeConstIterator hilti::rt::stream::View::end() const {
    assert(_begin.chain());
    return _end ? *_end : _begin.chain()->end();
}
const hilti::rt::stream::SafeConstIterator& hilti::rt::stream::View::cbegin() const { return _begin; }
const hilti::rt::stream::SafeConstIterator& hilti::rt::stream::View::begin() const { return _begin; }
hilti::rt::stream::detail::UnsafeConstIterator hilti::rt::stream::View::unsafeEnd() const {
    return _end ? detail::UnsafeConstIterator(*_end) : _begin.chain()->unsafeEnd();
}
hilti::rt::stream::detail::UnsafeConstIterator hilti::rt::stream::View::unsafeBegin() const {
    return detail::UnsafeConstIterator(_begin);
}
hilti::rt::stream::View hilti::rt::stream::View::extract(Byte* dst, uint64_t n) const {
    _ensureValid();

    if ( n > size() )
        throw WouldBlock("end of stream view");

    const auto p = begin();

    const auto* chain = p.chain();
    assert(chain);
    assert(chain->isValid());
    assert(chain->inRange(p.offset()));

    auto offset = p.offset().Ref();

    for ( auto c = chain->findChunk(p.offset()); offset - p.offset().Ref() < n; c = c->next() ) {
        assert(c);

        const auto into_chunk = offset - c->offset().Ref();
        const auto remaining = n + p.offset().Ref() - offset;
        const auto m = std::min(remaining, c->size().Ref() - into_chunk);

        ::memcpy(dst, c->data(offset), m);
        offset += m;
        dst += m;
    }

    return View(p + n, _end);
}
hilti::rt::stream::View hilti::rt::stream::View::limit(Offset offset) const {
    // We cannot increase the size of an already limited view.
    if ( _end ) {
        const auto size = _end->offset().Ref() - _begin.offset().Ref();
        offset = std::min(offset.Ref(), size);
    }

    return View(begin(), begin() + offset);
}
hilti::rt::stream::View hilti::rt::stream::View::trim(const SafeConstIterator& nbegin) const {
    _ensureSameChain(nbegin);

    if ( ! _end )
        return View(nbegin);

    if ( nbegin.offset() > _end->offset() )
        return View(*_end, *_end);

    return View(nbegin, *_end);
}
hilti::rt::stream::SafeConstIterator hilti::rt::stream::View::at(const Offset& offset) const {
    return begin() + (offset - begin().offset());
}
hilti::rt::stream::View hilti::rt::stream::View::sub(const Offset& to) const { return View(begin(), begin() + to); }
hilti::rt::stream::View hilti::rt::stream::View::sub(const Offset& from, const Offset& to) const {
    return View(begin() + from, begin() + to);
}
hilti::rt::stream::View hilti::rt::stream::View::sub(SafeConstIterator to) const {
    _ensureSameChain(to);
    return View(begin(), std::move(to));
}
hilti::rt::stream::View hilti::rt::stream::View::sub(SafeConstIterator from, SafeConstIterator to) const {
    _ensureSameChain(from);
    _ensureSameChain(to);
    return View(std::move(from), std::move(to));
}
hilti::rt::stream::View hilti::rt::stream::View::advance(const integer::safe<uint64_t>& i) const {
    return View(begin() + i, _end);
}
hilti::rt::stream::View hilti::rt::stream::View::advance(SafeConstIterator i) const {
    _ensureSameChain(i);
    return View(std::move(i), _end);
}
std::tuple<bool, UnsafeConstIterator> hilti::rt::stream::View::find(const Bytes& v, UnsafeConstIterator n,
                                                                    Direction d) const {
    if ( d == Direction::Forward )
        return _findForward(v, n);
    else
        return _findBackward(v, n);
}
std::tuple<bool, SafeConstIterator> hilti::rt::stream::View::find(const Bytes& v, const SafeConstIterator& n,
                                                                  Direction d) const {
    _ensureValid();
    _ensureSameChain(n);
    auto x = find(v, UnsafeConstIterator(n), d);
    return std::make_tuple(std::get<0>(x), SafeConstIterator(std::get<1>(x)));
}
std::tuple<bool, SafeConstIterator> hilti::rt::stream::View::find(const Bytes& v, Direction d) const {
    _ensureValid();
    auto i = (d == Direction::Forward ? unsafeBegin() : unsafeEnd());
    auto x = find(v, i, d);
    return std::make_tuple(std::get<0>(x), SafeConstIterator(std::get<1>(x)));
}
std::tuple<bool, SafeConstIterator> hilti::rt::stream::View::find(const View& v, const SafeConstIterator& n) const {
    _ensureValid();
    _ensureSameChain(n);
    auto x = find(v, UnsafeConstIterator(n));
    return std::make_tuple(std::get<0>(x), SafeConstIterator(std::get<1>(x)));
}
std::tuple<bool, SafeConstIterator> hilti::rt::stream::View::find(const View& v) const {
    _ensureValid();
    auto x = find(v, UnsafeConstIterator());
    return std::make_tuple(std::get<0>(x), SafeConstIterator(std::get<1>(x)));
}
hilti::rt::stream::SafeConstIterator hilti::rt::stream::View::find(Byte b, const SafeConstIterator& n) const {
    _ensureValid();
    _ensureSameChain(n);
    return SafeConstIterator(find(b, UnsafeConstIterator(n)));
}
hilti::rt::stream::SafeConstIterator hilti::rt::stream::View::find(Byte b) const {
    _ensureValid();
    return SafeConstIterator(find(b, UnsafeConstIterator()));
}
bool hilti::rt::stream::View::isOpenEnded() const { return ! _end.has_value(); }
bool hilti::rt::stream::View::isEmpty() const { return size() == 0; }
std::optional<Offset> hilti::rt::stream::View::endOffset() const {
    if ( _end )
        return _end->offset();
    else
        return std::nullopt;
}
hilti::rt::stream::View::Offset hilti::rt::stream::View::offset() const { return _begin.offset(); }
hilti::rt::stream::View::View(SafeConstIterator begin) : _begin(std::move(begin)) {}
hilti::rt::stream::View::View(SafeConstIterator begin, SafeConstIterator end)
    : _begin(std::move(begin)), _end(std::move(end)) {
    _ensureValid();

    if ( ! _end->_chain )
        _end = _begin.chain()->end();
    else
        _ensureSameChain(*_end);
}
std::ostream& hilti::rt::stream::operator<<(std::ostream& out, const View& x) {
    return out << hilti::rt::to_string_for_print(x);
}
hilti::rt::Bytes hilti::rt::stream::View::data() const {
    Bytes s;
    s.append(*this);
    return s;
}
hilti::rt::stream::View::Size hilti::rt::stream::View::size() const {
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
void hilti::rt::stream::View::_ensureValid() const {
    if ( ! _begin.isValid() )
        throw InvalidIterator("view has invalid beginning");

    if ( (! _begin.isUnset()) && _begin.offset() < _begin.chain()->offset() )
        throw InvalidIterator("view starts before available range");

    if ( _end && ! _end->isValid() )
        throw InvalidIterator("view has invalid end");
}
void hilti::rt::stream::View::_ensureSameChain(const SafeConstIterator& other) const {
    if ( _begin.chain() != other.chain() )
        throw InvalidIterator("incompatible iterator");
}
hilti::rt::stream::View::View(SafeConstIterator begin, std::optional<SafeConstIterator> end)
    : _begin(std::move(begin)), _end(std::move(end)) {
    if ( _end )
        _ensureSameChain(*_end);
}
bool hilti::rt::Stream::operator!=(const Stream& other) const { return ! (*this == other); }
bool hilti::rt::Stream::operator!=(const Bytes& other) const { return ! (*this == other); }
bool hilti::rt::Stream::operator==(const stream::View& other) const { return view() == other; }
bool hilti::rt::Stream::operator==(const Stream& other) const { return view() == other.view(); }
bool hilti::rt::Stream::operator==(const Bytes& other) const { return view() == other; }
hilti::rt::Stream::View hilti::rt::Stream::view(bool expanding) const {
    return expanding ? View(begin()) : View(begin(), end());
}
hilti::rt::Stream::Offset hilti::rt::Stream::endOffset() const { return _chain->endOffset(); }
hilti::rt::Stream::SafeConstIterator hilti::rt::Stream::at(const Offset& offset) const { return _chain->at(offset); }
hilti::rt::Stream::UnsafeConstIterator hilti::rt::Stream::unsafeEnd() const { return _chain->unsafeEnd(); }
hilti::rt::Stream::UnsafeConstIterator hilti::rt::Stream::unsafeBegin() const { return _chain->unsafeBegin(); }
hilti::rt::Stream::SafeConstIterator hilti::rt::Stream::cend() const { return end(); }
hilti::rt::Stream::SafeConstIterator hilti::rt::Stream::end() const { return _chain->end(); }
hilti::rt::Stream::SafeConstIterator hilti::rt::Stream::cbegin() const { return begin(); }
hilti::rt::Stream::SafeConstIterator hilti::rt::Stream::begin() const { return _chain->begin(); }
void hilti::rt::Stream::makeOwning() {
    // Only the final chunk can be non-owning, that's guaranteed by
    // `Chunk::setNext()`.
    if ( auto* t = _chain->tail() )
        t->makeOwning();
}
void hilti::rt::Stream::reset() { _chain->reset(); }
bool hilti::rt::Stream::isFrozen() const { return _chain->isFrozen(); }
void hilti::rt::Stream::unfreeze() { _chain->unfreeze(); }
void hilti::rt::Stream::freeze() { _chain->freeze(); }
void hilti::rt::Stream::trim(const SafeConstIterator& i) { _chain->trim(i); }
bool hilti::rt::Stream::isEmpty() const { return _chain->size() == 0; }
hilti::rt::Stream::Size hilti::rt::Stream::size() const { return _chain->size(); }
hilti::rt::Stream::~Stream() {
    assert(_chain);
    _chain->invalidate();
}
hilti::rt::Stream& hilti::rt::Stream::operator=(const Stream& other) {
    if ( &other == this )
        return *this;

    _chain->invalidate();
    _chain = other._chain->copy();
    return *this;
}
hilti::rt::Stream& hilti::rt::Stream::operator=(Stream&& other) noexcept {
    if ( &other == this )
        return *this;

    _chain->invalidate();
    _chain = std::move(other._chain);
    other._chain = make_intrusive<Chain>();
    return *this;
}
hilti::rt::Stream::Stream(Stream&& other) noexcept : _chain(std::move(other._chain)) {
    other._chain = make_intrusive<Chain>();
}
hilti::rt::Stream::Stream(const Stream& other) : _chain(other._chain->copy()) {}
hilti::rt::Stream::Stream(const stream::View& d) : Stream(Chunk(0, d)) {}
hilti::rt::Stream::Stream(const char* d, Size n, stream::NonOwning) : Stream() { append(d, n, stream::NonOwning()); }
hilti::rt::Stream::Stream(const char* d, Size n) : Stream() { append(d, n); }
hilti::rt::Stream::Stream() : _chain(make_intrusive<Chain>()) {}
int hilti::rt::Stream::numberOfChunks() const { return _chain->numberOfChunks(); }
bool hilti::rt::Stream::operator!=(const stream::View& other) const { return ! (*this == other); }
hilti::rt::Stream::Stream(Chunk&& ch) : _chain(make_intrusive<Chain>(std::make_unique<Chunk>(std::move(ch)))) {}
const hilti::rt::stream::Statistics& hilti::rt::Stream::statistics() const { return _chain->statistics(); }
std::ostream& hilti::rt::operator<<(std::ostream& out, const stream::Statistics& x) {
    return out << to_string_for_print(x);
}
std::ostream& hilti::rt::operator<<(std::ostream& out, const Stream& x) { return out << to_string_for_print(x); }
std::string hilti::rt::detail::adl::to_string(const stream::View& x, adl::tag /*unused*/) {
    return fmt("b\"%s\"", hilti::rt::to_string_for_print(x));
}
std::string hilti::rt::detail::adl::to_string(const stream::Statistics& x, adl::tag /*unused*/) {
    // Render like a struct.
    return fmt("[$num_data_bytes=%" PRIu64 ", $num_data_chunks=%" PRIu64 ", $num_gap_bytes=%" PRIu64
               ", $num_gap_chunks=%" PRIu64 "]",
               x.num_data_bytes, x.num_data_chunks, x.num_gap_bytes, x.num_gap_chunks);
}
std::string hilti::rt::detail::adl::to_string(const Stream& x, adl::tag /*unused*/) {
    return hilti::rt::to_string(x.view());
}
