// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

using namespace hilti::rt;
using namespace hilti::rt::stream;
using namespace hilti::rt::stream::detail;

Chunk::Chunk(Offset offset, const View& d) : _offset(offset) {
    if ( d.size() <= SmallBufferSize ) {
        std::array<Byte, SmallBufferSize> a{};
        d.copyRaw(a.data());
        _data = std::make_pair(d.size(), a);
    }
    else {
        std::vector<Byte> v;
        v.resize(d.size());
        d.copyRaw(v.data());
        _data = std::move(v);
    }
}

Chunk::Chunk(Offset offset, const std::string& s) : _offset(offset) {
    if ( s.size() <= SmallBufferSize ) {
        std::array<Byte, SmallBufferSize> a{};
        memcpy(a.data(), s.data(), s.size());
        _data = std::make_pair(s.size(), a);
    }
    else {
        std::vector<Byte> v;
        v.resize(s.size());
        memcpy(v.data(), s.data(), s.size());
        _data = std::move(v);
    }
}

void Chunk::trim(Offset o) {
    assert(o >= _offset && o < _offset + size());
    if ( auto a = std::get_if<Array>(&_data) ) {
        auto begin = a->second.data() + (o - _offset).Ref();
        auto end = a->second.data() + a->first.Ref();
        a->first = (end - begin);
        memmove(a->second.data(), begin, a->first.Ref());
    }
    else {
        auto& v = std::get<Vector>(_data);
        v.erase(v.begin(), v.begin() + (o - _offset).Ref());
    }

    _offset = o;
}

const Chunk* Chain::findChunk(Offset offset, const Chunk* hint_prev) const {
    _ensureValid();

    const Chunk* c = _head.get();

    if ( hint_prev && hint_prev->offset() <= offset )
        c = hint_prev;

    while ( c && ! c->inRange(offset) )
        c = c->next();

    if ( c && ! c->inRange(offset) )
        return nullptr;

    return c;
}

Chunk* Chain::findChunk(Offset offset, Chunk* hint_prev) {
    _ensureValid();

    Chunk* c = _head.get();

    if ( hint_prev && hint_prev->offset() <= offset )
        c = hint_prev;

    while ( c && ! c->inRange(offset) )
        c = c->next();

    if ( _tail && offset > _tail->endOffset() )
        return _tail;

    return c;
}

const Byte* Chain::data(Offset offset, Chunk* hint_prev) const {
    auto c = findChunk(offset, hint_prev);
    if ( ! c )
        throw InvalidIterator("stream iterator outside of valid range");

    return c->data(offset);
}

void Chain::append(std::unique_ptr<Chunk> chunk) {
    _ensureValid();
    _ensureMutable();

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

    _tail->setNext(std::move(other._head));
    _tail = other._tail;
    other.reset();
}

void Chain::trim(Offset offset) {
    _ensureValid();

    // We search the first chunk that's containing the desired position,
    // deleting all the ones we pass on the way. We trim the one that
    // contains the position.
    while ( _head ) {
        if ( offset >= _head->endOffset() ) {
            // Delete chunk.
            _head = std::move(_head->_next);
            if ( ! _head || _head->isLast() )
                _tail = _head.get();
        }

        else if ( _head->inRange(offset) ) {
            _head->trim(offset);
            assert(_head->offset() == offset);
            break;
        }
    }

    _head_offset = offset;
    assert(! _head || _head->offset() == offset);
}

ChainPtr Chain::deepCopy() const {
    _ensureValid();

    auto nchain = make_intrusive<Chain>();

    auto c = _head.get();
    while ( c ) {
        nchain->append(std::make_unique<Chunk>(*c));
        c = c->next();
    }

    return nchain;
}

int Chain::numberOfChunks() const {
    int n = 0;
    for ( auto ch = _head.get(); ch; ch = ch->_next.get() )
        ++n;

    return n;
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

std::tuple<bool, UnsafeConstIterator> View::find(const Bytes& v, UnsafeConstIterator n) const {
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

bool View::startsWith(const Bytes& b) const {
    _ensureValid();
    auto s1 = unsafeBegin();
    auto e1 = unsafeEnd();
    auto s2 = b.begin();
    auto e2 = b.end();

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

    if ( unsafeBegin() == unsafeEnd() || ! unsafeBegin().chunk() )
        return {};

    auto chunk = _begin.chain()->findChunk(_begin.offset(), _begin.chunk());
    if ( ! chunk )
        throw InvalidIterator("stream iterator outside of valid range");

    auto start = chunk->data() + (_begin.offset() - chunk->offset()).Ref();
    bool is_last = (chunk->isLast() || (_end && _end->offset() <= chunk->endOffset()));

    Size size;

    if ( _end && is_last ) {
        auto offset_end = std::min(_end->offset(), _begin.chain()->endOffset());
        size = (offset_end - _begin.offset());
    }
    else
        size = chunk->endData() - start;

    return View::Block{.start = start,
                       .size = size,
                       .offset = _begin.offset(),
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
        auto offset_end = std::min(_end->offset(), _begin.chain()->endOffset());
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

Stream::Stream(const Bytes& d) : Stream(Chunk(0, d.str())) {}

void Stream::append(Bytes&& data) {
    if ( data.isEmpty() )
        return;

    _chain->append(std::make_unique<Chunk>(0, data.str()));
}

void Stream::append(const Bytes& data) {
    if ( data.isEmpty() )
        return;

    _chain->append(std::make_unique<Chunk>(0, data.str()));
}

void Stream::append(const char* data, size_t len) {
    if ( ! len )
        return;

    _chain->append(std::make_unique<Chunk>(0, std::string(data, len)));
}

Size View::size() const {
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

std::string Stream::data() const { return view().data().str(); }

Bytes stream::View::data() const {
    Bytes s;

    for ( auto block = firstBlock(); block; block = nextBlock(block) )
        s.append(std::string(reinterpret_cast<const char*>(block->start), block->size));

    return s;
}

bool stream::View::operator==(const Stream& other) const { return *this == other.view(); }

bool stream::View::operator==(const View& other) const {
    if ( size() != other.size() )
        return false;

    auto i = unsafeBegin();
    auto j = other.unsafeBegin();

    while ( i != unsafeEnd() ) {
        if ( *i++ != *j++ )
            return false;
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

    out << "[data]" << std::endl;
    Stream::debugPrint(out, _begin.chain());
}

void Stream::debugPrint(std::ostream& out, const stream::detail::Chain* chain) {
    out << fmt("chain %p", chain) << std::endl;
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
    out << fmt("offset %lu  data=|%s|", _offset, x) << std::endl;
}
