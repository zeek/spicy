// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>

namespace hilti::rt::vthread {

/** Type for the unique IDs of virtual threads. */
using ID = int64_t;

/** ID of original (main) thread. */
inline const ID Master = -1;

} // namespace hilti::rt::vthread
