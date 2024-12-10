// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace unicode {

/* When processing unicode, how to handle invalid data not representing unicode codepoints. */
HILTI_RT_ENUM_WITH_DEFAULT(DecodeErrorStrategy, IGNORE,
                           IGNORE,  // skip data
                           REPLACE, // replace with a place-holder
                           STRICT   // throw a runtime error
);

/** For bytes decoding, which character set to use. */
HILTI_RT_ENUM(Charset, Undef, UTF8, ASCII);

} // namespace unicode

namespace detail::adl {
std::string to_string(const unicode::DecodeErrorStrategy& x, adl::tag /*unused*/);
std::string to_string(const unicode::Charset& x, adl::tag /*unused*/);
} // namespace detail::adl

} // namespace hilti::rt
