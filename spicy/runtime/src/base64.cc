// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/types/bytes.h>

#include <spicy/rt/base64.h>

extern "C" {
#include <b64/cdecode.h>
#include <b64/cencode.h>
}

using namespace spicy::rt;
using namespace spicy::rt::base64;

struct detail::State {
    base64_encodestate estate;
    base64_decodestate dstate;
};

Stream::Stream() {
    _state = std::shared_ptr<detail::State>(new detail::State(), [](auto p) {
        // Nothing else to clean up.
        delete p; // NOLINT(cppcoreguidelines-owning-memory)
    });

    base64_init_encodestate(&_state->estate);
    base64_init_decodestate(&_state->dstate);
}

// Don't finish the stream here, it might be shared with other instances.
// It'll eventually be cleaned up.
Stream::~Stream() = default;

hilti::rt::Bytes Stream::encode(const hilti::rt::Bytes& data) {
    if ( ! _state )
        throw Base64Error("encoding already finished");

    char buf[static_cast<uint64_t>(data.size() * 2)];
    auto len = base64_encode_block(data.data(), static_cast<int>(data.size()), buf, &_state->estate);
    return hilti::rt::Bytes(buf, len);
}

hilti::rt::Bytes Stream::encode(const hilti::rt::stream::View& data) {
    if ( ! _state )
        throw Base64Error("encoding already finished");

    hilti::rt::Bytes encoded;

    for ( auto block = data.firstBlock(); block; block = data.nextBlock(block) ) {
        char buf[static_cast<uint64_t>(block->size * 2)];
        auto len = base64_encode_block(reinterpret_cast<const char*>(block->start), static_cast<int>(block->size), buf,
                                       &_state->estate);
        encoded.append(hilti::rt::Bytes(buf, len));
    }

    return encoded;
}

hilti::rt::Bytes Stream::decode(const hilti::rt::Bytes& data) {
    if ( ! _state )
        throw Base64Error("decoding already finished");

    char buf[static_cast<uint64_t>(data.size() * 2)];
    auto len = base64_decode_block(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), buf,
                                   &_state->dstate);

    return hilti::rt::Bytes(buf, len);
}

hilti::rt::Bytes Stream::decode(const hilti::rt::stream::View& data) {
    if ( ! _state )
        throw Base64Error("decoding already finished");

    hilti::rt::Bytes decoded;

    for ( auto block = data.firstBlock(); block; block = data.nextBlock(block) ) {
        char buf[static_cast<uint64_t>(block->size * 2)];
        auto len = base64_decode_block(reinterpret_cast<const char*>(block->start), static_cast<int>(block->size), buf,
                                       &_state->dstate);
        decoded.append(hilti::rt::Bytes(buf, len));
    }

    return decoded;
}

hilti::rt::Bytes Stream::finish() {
    if ( ! _state )
        throw Base64Error("stream already finished");

    // This can be safely called for both encoding and decoding, but won't do
    // anything for the latter.
    hilti::rt::Bytes b;
    char buf[4];

    auto len = base64_encode_blockend(buf, &_state->estate);
    b.append(hilti::rt::Bytes(buf, len));

    _state = nullptr;
    return b;
}
