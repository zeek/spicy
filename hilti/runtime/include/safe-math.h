// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// Wrapper around functionality from 3rdparty's safe-math that we need. This
// needs to be in a separate implementation file because one cannot include
// both SafeInt.h and safe-math.h at the same time.

#pragma once

#include <cstdint>

namespace hilti::rt::integer {

/**
 * Negates an unsigned value, returning a signed value. Will through a
 * `OutOfRange` if not possible.
 */
extern int64_t safe_negate(uint64_t x);

} // namespace hilti::rt::integer
