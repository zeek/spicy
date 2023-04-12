// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

namespace spicy::rt::zlib {

namespace detail {
struct State;
} // namespace detail

/** Thrown when something goes wrong with uncompressiong. */
class ZlibError : public hilti::rt::RuntimeError {
    using hilti::rt::RuntimeError::RuntimeError;
};

/**
 * State for streaming gzip decompression.
 */
class Stream {
public:
    /**
     * Constructor initializing a new stream for decompression.
     *
     * @param windows_bits value corresponding to zlib's `windowBits` parameter
     * for `inflateInit2`; the default means "check for, and require, a gzip
     * file"
     */
    Stream(int64_t window_bits = 15 + 32);
    ~Stream();

    Stream(const Stream&) = default;
    Stream(Stream&&) noexcept = default;
    Stream& operator=(const Stream&) = default;
    Stream& operator=(Stream&&) noexcept = default;

    /**
     * Decompresses a chunk of data. Each chunk will continue where the
     * previous one left off.
     *
     * @param data next chunk of data to decompress
     * @return newly decompressed data
     */
    hilti::rt::Bytes decompress(const hilti::rt::Bytes& data);

    /**
     * Decompresses a chunk of data. Each chunk will continue where the
     * previous one left off.
     *
     * @param data next chunk of data to decompress
     * @return newly decompressed data
     */
    hilti::rt::Bytes decompress(const hilti::rt::stream::View& data);

    /**
     * Signals the end of decompression.
     *
     * @return any additional data becoming available at the end of the process
     */
    hilti::rt::Bytes finish();

private:
    std::shared_ptr<detail::State> _state;
};

/** Instantiates a new `Stream` object, forwarding arguments to its constructor. */
inline Stream init(int64_t window_bits) // NOLINT(google-runtime-references)
{
    return Stream(window_bits);
}

/** Forwards to the corresponding `Stream` method. */
inline hilti::rt::Bytes decompress(Stream& stream, // NOLINT(google-runtime-references)
                                   const hilti::rt::Bytes& data) {
    return stream.decompress(data);
}

/** Forwards to the corresponding `Stream` method. */
inline hilti::rt::Bytes decompress(Stream& stream, // NOLINT(google-runtime-references)
                                   const hilti::rt::stream::View& data) {
    return stream.decompress(data);
}

/** Forwards to the corresponding `Stream` method. */
inline hilti::rt::Bytes finish(Stream& stream) // NOLINT(google-runtime-references)
{
    return stream.finish();
}

/** Returns initial seed for CRC32 computation. */
extern uint64_t crc32_init();

/** Computes rolling CRC32 computation adding another chunk of data. */
extern uint64_t crc32_add(uint64_t crc, const hilti::rt::Bytes& data);

} // namespace spicy::rt::zlib

namespace hilti::rt::detail::adl {
extern inline std::string to_string(const spicy::rt::zlib::Stream& /* x */, adl::tag /*unused*/) {
    return "<zlib stream>";
}
} // namespace hilti::rt::detail::adl
