// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>

namespace hilti::rt {

namespace vthread {

/** Type for the unique IDs of virtual threads. */
using ID = int64_t;

/** ID of original (main) thread. */
inline const ID Master = -1;

} // namespace vthread

} // namespace hilti::rt
