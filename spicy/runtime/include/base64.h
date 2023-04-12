// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/rt/exception.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

namespace spicy::rt::base64 {

namespace detail {
struct State;
} // namespace detail

/** Thrown when something goes wrong with uncompressing. */
class Base64Error : public hilti::rt::RuntimeError {
    using hilti::rt::RuntimeError::RuntimeError;
};

/**
 * State for streaming base64 encoding/decoding. Each instance may be be used
 * only for either for encoding or decoding.
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
     * Encode a chunk of data. Each chunk will continue where the previous
     * one left off.
     *
     * @param data next chunk of data to encode
     * @return newly encoded data
     */
    hilti::rt::Bytes encode(const hilti::rt::Bytes& data);

    /**
     * Encode a chunk of data. Each chunk will continue where the previous
     * one left off.
     *
     * @param data next chunk of data to encode
     * @return newly encoded data
     */
    hilti::rt::Bytes encode(const hilti::rt::stream::View& data);

    /**
     * Decode a chunk of data. Each chunk will continue where the previous
     * one left off.
     *
     * @param data next chunk of data to decode
     * @return newly encoded data
     */
    hilti::rt::Bytes decode(const hilti::rt::Bytes& data);

    /**
     * Decode a chunk of data. Each chunk will continue where the previous
     * one left off.
     *
     * @param data next chunk of data to decode
     * @return newly encoded data
     */
    hilti::rt::Bytes decode(const hilti::rt::stream::View& data);

    /**
     * Signals the end of encoding/decoding.
     *
     * @return any additional data becoming available at the end of the process
     */
    hilti::rt::Bytes finish();

private:
    std::shared_ptr<detail::State> _state;
};

/** Forwards to the corresponding `Stream` method. */
inline hilti::rt::Bytes encode(Stream& stream, // NOLINT(google-runtime-references)
                               const hilti::rt::Bytes& data) {
    return stream.encode(data);
}

/** Forwards to the corresponding `Stream` method. */
inline hilti::rt::Bytes encode(Stream& stream, // NOLINT(google-runtime-references)
                               const hilti::rt::stream::View& data) {
    return stream.encode(data);
}

/** Forwards to the corresponding `Stream` method. */
inline hilti::rt::Bytes decode(Stream& stream, // NOLINT(google-runtime-references)
                               const hilti::rt::Bytes& data) {
    return stream.decode(data);
}

/** Forwards to the corresponding `Stream` method. */
inline hilti::rt::Bytes decode(Stream& stream, // NOLINT(google-runtime-references)
                               const hilti::rt::stream::View& data) {
    return stream.decode(data);
}

/** Forwards to the corresponding `Stream` method. */
inline hilti::rt::Bytes finish(Stream& stream) // NOLINT(google-runtime-references)
{
    return stream.finish();
}

} // namespace spicy::rt::base64

namespace hilti::rt::detail::adl {
extern inline std::string to_string(const spicy::rt::base64::Stream& /* x */, adl::tag /*unused*/) {
    return "<base64 stream>";
}
} // namespace hilti::rt::detail::adl
