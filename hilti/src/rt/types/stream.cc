// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include "rt/types/stream.h"

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>

using namespace hilti::rt;
using namespace hilti::rt::stream;
using namespace hilti::rt::stream::detail;

Chunk::Chunk(const View& d) : _offset(0) {
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

Chunk::Chunk(const std::string& s) : _offset(0) {
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

bool Chunk::tryAppend(const Chunk& d) {
    if ( ! isCompact() )
        return false;

    auto& a = std::get<Array>(_data);

    auto nsize = a.first + d.size();

    if ( nsize > SmallBufferSize )
        return false;

    memcpy(a.second.data() + a.first.Ref(), d.begin(), d.size());
    a.first = nsize;
    return true;
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

SafeConstIterator View::find(Byte b, const SafeConstIterator& n) const {
    for ( auto i = UnsafeConstIterator(n ? n : _begin); i != UnsafeConstIterator(safeEnd()); ++i ) {
        if ( *i == b )
            return SafeConstIterator(i);
    }

    return safeEnd();
}

std::tuple<bool, SafeConstIterator> View::find(const View& v, const SafeConstIterator& n) const {
    if ( v.isEmpty() )
        return std::make_tuple(true, n ? n : _begin);

    auto first = *v.safeBegin();

    for ( auto i = UnsafeConstIterator(n ? n : _begin); true; ++i ) {
        if ( i == UnsafeConstIterator(safeEnd()) )
            return std::make_tuple(false, SafeConstIterator(i));

        if ( *i != first )
            continue;

        auto x = i;
        auto y = UnsafeConstIterator(v._begin);

        for ( ;; ) {
            if ( x == UnsafeConstIterator(safeEnd()) )
                return std::make_tuple(false, SafeConstIterator(i));

            if ( *x++ != *y++ )
                break;

            if ( y == UnsafeConstIterator(v.safeEnd()) )
                return std::make_tuple(true, SafeConstIterator(i));
        }
    }
}

std::tuple<bool, SafeConstIterator> View::find(const Bytes& v, const SafeConstIterator& n) const {
    if ( v.isEmpty() )
        return std::make_tuple(true, n ? n : _begin);

    auto first = *v.begin();

    for ( auto i = UnsafeConstIterator(n ? n : _begin); true; ++i ) {
        if ( i == UnsafeConstIterator(safeEnd()) )
            return std::make_tuple(false, SafeConstIterator(i));

        if ( *i != first )
            continue;

        auto x = i;
        auto y = v.begin();

        for ( ;; ) {
            if ( x == UnsafeConstIterator(safeEnd()) )
                return std::make_tuple(false, SafeConstIterator(i));

            if ( *x++ != *y++ )
                break;

            if ( y == v.end() )
                return std::make_tuple(true, SafeConstIterator(i));
        }
    }
}

bool View::startsWith(const Bytes& b) const {
    auto s1 = begin();
    auto e1 = end();
    auto s2 = b.begin();
    auto e2 = b.end();

    while ( s1 != e1 && s2 != e2 ) {
        if ( *s1++ != *s2++ )
            return false;
    }

    return s2 == e2;
}

void View::copyRaw(Byte* dst) const {
    for ( auto i = begin(); i != end(); ++i )
        *dst++ = *i;
}

std::optional<View::Block> View::firstBlock() const {
    if ( begin() == end() )
        return {};

    auto chunk = begin().chunk();
    bool is_last = chunk->isLast();

    if ( _end && _end->offset() <= chunk->offset() + chunk->size() )
        is_last = true;

    return View::Block{.start = chunk->begin() + (_begin.offset() - chunk->offset()).Ref(),
                       .size = chunk->size() - (_begin.offset() - chunk->offset()),
                       .offset = _begin.offset(),
                       .is_first = true,
                       .is_last = is_last,
                       ._block = (is_last ? nullptr : chunk)};
}

std::optional<View::Block> View::nextBlock(std::optional<Block> current) const {
    if ( ! (current && current->_block) )
        return {};

    const Chunk* chunk = current->_block->next().get();
    auto chunk_start_offset = chunk->offset();
    auto chunk_end_offset = chunk->offset() + chunk->size();

    bool is_last = false;

    if ( end().offset() >= chunk_start_offset && end().offset() <= chunk_end_offset )
        is_last = true;

    if ( is_last ) {
        uint64_t size;

        if ( end().offset() < chunk_end_offset )
            size = (end().offset() - chunk_start_offset);
        else
            size = chunk->size();

        return View::Block{.start = chunk->begin(),
                           .size = size,
                           .offset = chunk->offset(),
                           .is_first = false,
                           .is_last = true,
                           ._block = nullptr};
    }
    else {
        return View::Block{.start = chunk->begin(),
                           .size = chunk->size(),
                           .offset = chunk->offset(),
                           .is_first = false,
                           .is_last = false,
                           ._block = chunk};
    }
}

Stream::Stream(const Bytes& d) : Stream(Chunk(d.str())) {}

int Stream::numberChunks() const {
    int n = 0;
    for ( auto ch = _content->head; ch; ch = ch->next() )
        ++n;

    return n;
}

void Stream::appendContent(Content&& ocontent) {
    auto& ch = _content;
    auto& och = ocontent;

    size_t offset = end().offset();

    for ( auto x = och->head; x; x = x->next() )
        x->setOffset(x->offset() + offset);

    ch->tail->setNext(std::move(och->head));
    ch->tail = std::move(och->tail);
}

void Stream::append(Bytes&& data) {
    if ( data.isEmpty() )
        return;

    if ( _frozen )
        throw Frozen("stream object is frozen");

    // TODO(robin): Optimize for moce.
    appendContent(std::make_shared<stream::detail::Chain>(data.str()));
}

void Stream::append(const Bytes& data) {
    if ( data.isEmpty() )
        return;

    if ( _frozen )
        throw Frozen("stream object is frozen");

    appendContent(std::make_shared<stream::detail::Chain>(data.str()));
}

void Stream::append(const char* data, size_t len) {
    if ( ! len )
        return;

    if ( _frozen )
        throw Frozen("stream object is frozen");

    appendContent(std::make_shared<stream::detail::Chain>(std::string(data, len)));
}

void Stream::trim(const stream::SafeConstIterator& i) {
    auto& ch = _content;

    // We search the first chunk that's containing the desired position, deleting
    // all the ones we pass on the way. We trim the one that contains the position.
    for ( auto c = ch->head; c; c = c->next() ) {
        if ( i.offset() >= c->offset() + c->size() ) {
            // Delete chunk.
            ch->head = c->next();
            if ( c->isLast() )
                ch->tail = c->next();

            if ( ! ch->head ) {
                // Just set the new head to empty chunk. Note that we need to
                // keep the current chain object so that iterators don't
                // become invalid.
                auto chain = _content;
                chain->head = chain->tail = std::shared_ptr<Chunk>(new Chunk(i.offset(), {}, 0));
                return;
            }

            continue;
        }

        if ( c->offset() <= i.offset() && i.offset() < c->offset() + c->size() ) {
            c->trim(i.offset());
            break;
        }
    }
}

void Stream::freeze() {
    _frozen = true;
    for ( auto c = head(); c; c = c->next().get() )
        c->freeze();
}

void Stream::unfreeze() {
    _frozen = false;
    for ( auto c = head(); c; c = c->next().get() )
        c->unfreeze();
}

int Stream::compare(UnsafeConstIterator s1, const UnsafeConstIterator& e1, UnsafeConstIterator s2,
                    const UnsafeConstIterator& e2) {
    while ( s1 != e1 && s2 != e2 ) {
        if ( auto c = (*s1++ - *s2++); c != 0 )
            return c;
    }

    if ( s1 != e1 )
        return 1;

    if ( s2 != e2 )
        return -1;

    return 0;
}

Stream::Content Stream::deepCopyContent() const {
    std::shared_ptr<Chunk> head;
    std::shared_ptr<Chunk> tail;

    for ( auto ch = _content->head; ch; ch = ch->next() ) {
        auto nch = std::make_shared<Chunk>(*ch);
        if ( tail )
            tail->setNext(nch);

        if ( ! head )
            head = nch;

        tail = nch;
    }

    return std::make_shared<stream::detail::Chain>(std::move(head), std::move(tail));
}

Size View::size() const {
    if ( safeEnd().offset() <= _begin.offset() )
        return 0;

    // Not so great: Because our end offset may point beyond what's currently
    // available, we actually need to iterate through and count.
    //
    // TODO(robin): We can build a better loop though.
    Size s = 0;
    auto x = safeEnd();
    auto end = detail::UnsafeConstIterator(safeEnd());
    for ( auto i = detail::UnsafeConstIterator(_begin); i != end; ++i )
        s++;

    return s;
}

std::string Stream::data() const {
    std::string s;
    s.reserve(size());

    for ( auto i = begin(); i != end(); ++i )
        s += static_cast<char>(*i);

    return s;
}

std::string stream::View::data() const {
    std::string s;
    s.reserve(size());

    for ( auto i = begin(); i != end(); ++i )
        s += static_cast<char>(*i);

    return s;
}

bool stream::View::operator==(const Stream& other) const { return *this == other.view(); }

bool stream::View::operator==(const View& other) const {
    if ( size() != other.size() )
        return false;

    auto i = begin();
    auto j = other.begin();

    while ( i != end() ) {
        if ( *i++ != *j++ )
            return false;
    }

    return true;
}

bool stream::View::operator==(const Bytes& other) const {
    if ( size() != other.size() )
        return false;

    auto i = begin();
    auto j = other.begin();

    while ( i != end() ) {
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

    auto c = _content.lock()->head.get();
    while ( c ) {
        if ( c == _chunk.lock().get() )
            break;

        chunk++;
        c = c->next().get();
    }

    if ( ! c )
        // Can happen if trimmed off.
        chunk = -1;

    out << fmt("iterator %p: parent=%p chunk=#%d offset=%llu is_end=%d\n", this, _content.lock().get(), chunk, _offset,
               static_cast<int>(isEnd()));
}

void UnsafeConstIterator::debugPrint(std::ostream& out) const {
    int chunk = 0;

    auto c = _content.lock()->head.get();
    while ( c ) {
        if ( c == _chunk )
            break;

        chunk++;
        c = c->next().get();
    }

    if ( ! c )
        // Can happen if trimmed off.
        chunk = -1;

    out << fmt("iterator %p: parent=%p chunk=#%d offset=%llu is_end=%d\n", this, _content.lock().get(), chunk, _offset,
               static_cast<int>(isEnd()));
}

void View::debugPrint(std::ostream& out) const {
    out << "[begin] ";
    _begin.debugPrint(out);

    out << "[end]   ";

    if ( _end )
        _end->debugPrint(out);
    else
        out << "<not set>";

    out << "[data]" << std::endl;
    Stream::debugPrint(out, _begin._content.lock().get());
}

void Stream::debugPrint(std::ostream& out, const stream::detail::Chain* chain) {
    out << fmt("chain %p", chain) << std::endl;
    int i = 0;
    for ( auto c = chain->head.get(); c; c = c->next().get() ) {
        out << fmt("  #%d: ", i++);
        c->debugPrint(out);
    }
}

void Stream::debugPrint(std::ostream& out) const { debugPrint(out, _content.get()); }

void Chunk::debugPrint(std::ostream& out) const {
    auto x = std::string(reinterpret_cast<const char*>(begin()), size());
    x = escapeBytes(x);
    out << fmt("offset %lu  frozen=%s  data=|%s|", _offset, (_frozen ? "yes" : "no"), x) << std::endl;
}
