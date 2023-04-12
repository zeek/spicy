// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <zlib.h>

#include <hilti/rt/types/bytes.h>

#include <spicy/rt/zlib_.h>

using namespace spicy::rt;
using namespace spicy::rt::zlib;

struct detail::State {
    z_stream stream;
};

Stream::Stream(int64_t window_bits) {
    _state = std::shared_ptr<detail::State>(new detail::State(), [](auto p) {
        inflateEnd(&p->stream);
        delete p; // NOLINT(cppcoreguidelines-owning-memory)
    });

    if ( inflateInit2(&_state->stream, window_bits) != Z_OK ) {
        _state = nullptr;
        throw ZlibError("inflateInit2 failed");
    }
}

// Don't finish the stream here, it might be shared with other instances.
Stream::~Stream() = default;

hilti::rt::Bytes Stream::finish() { return hilti::rt::Bytes(); }

hilti::rt::Bytes Stream::decompress(const hilti::rt::stream::View& data) {
    if ( ! _state )
        throw ZlibError("error'ed zlib stream cannot be reused");

    hilti::rt::Bytes decoded;

    for ( auto block = data.firstBlock(); block; block = data.nextBlock(block) ) {
        _state->stream.next_in = const_cast<Bytef*>(block->start);
        _state->stream.avail_in = block->size;

        do {
            char buf[4096];
            _state->stream.next_out = reinterpret_cast<unsigned char*>(buf);
            _state->stream.avail_out = sizeof(buf);

            int zip_status = inflate(&_state->stream, Z_SYNC_FLUSH);

            if ( zip_status != Z_STREAM_END && zip_status != Z_OK && zip_status != Z_BUF_ERROR ) {
                _state = nullptr;
                throw ZlibError("inflate failed");
            }

            if ( auto len = (sizeof(buf) - _state->stream.avail_out) )
                decoded.append(hilti::rt::Bytes(buf, static_cast<int>(len)));

            if ( zip_status == Z_STREAM_END ) {
                break;
            }

        } while ( _state->stream.avail_out == 0 );
    }

    return decoded;
}

hilti::rt::Bytes Stream::decompress(const hilti::rt::Bytes& data) {
    if ( ! _state )
        throw ZlibError("error'ed zlib stream cannot be reused");

    hilti::rt::Bytes decoded;

    _state->stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data.data()));
    _state->stream.avail_in = data.size();

    do {
        char buf[4096];
        _state->stream.next_out = reinterpret_cast<unsigned char*>(buf);
        _state->stream.avail_out = sizeof(buf);

        int zip_status = inflate(&_state->stream, Z_SYNC_FLUSH);

        if ( zip_status != Z_STREAM_END && zip_status != Z_OK && zip_status != Z_BUF_ERROR ) {
            _state = nullptr;
            throw ZlibError("inflate failed");
        }

        if ( auto len = (sizeof(buf) - _state->stream.avail_out) )
            decoded.append(hilti::rt::Bytes(buf, static_cast<int>(len)));

        if ( zip_status == Z_STREAM_END ) {
            break;
        }

    } while ( _state->stream.avail_out == 0 );

    return decoded;
}

uint64_t zlib::crc32_init() { return ::crc32(0L, Z_NULL, 0); }

uint64_t zlib::crc32_add(uint64_t crc, const hilti::rt::Bytes& data) {
    return ::crc32(crc, reinterpret_cast<const Bytef*>(data.data()), data.size());
}
