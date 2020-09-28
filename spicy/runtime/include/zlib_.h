// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

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
    Stream();
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

} // namespace spicy::rt::zlib

namespace hilti::rt::detail::adl {
extern inline std::string to_string(const spicy::rt::zlib::Stream& /* x */, adl::tag /*unused*/) {
    return "<zlib stream>";
}
} // namespace hilti::rt::detail::adl
