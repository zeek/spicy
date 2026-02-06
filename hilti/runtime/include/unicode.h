// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace unicode {

/* When processing unicode, how to handle invalid data not representing unicode codepoints. */
HILTI_RT_ENUM(DecodeErrorStrategy,
              IGNORE,  // skip data
              REPLACE, // replace with a place-holder
              STRICT,  // throw a runtime error
              Undef = -1);

/** For bytes decoding, which character set to use. */
HILTI_RT_ENUM(Charset, UTF8, UTF16LE, UTF16BE, ASCII, Undef = -1);

constexpr uint32_t REPLACEMENT_CHARACTER = 0x0000FFFD;

} // namespace unicode

namespace detail::adl {
std::string to_string(const unicode::DecodeErrorStrategy& x, adl::tag /*unused*/);
std::string to_string(const unicode::Charset& x, adl::tag /*unused*/);
} // namespace detail::adl

} // namespace hilti::rt
