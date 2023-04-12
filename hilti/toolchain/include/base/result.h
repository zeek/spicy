// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/result.h>

namespace hilti {
namespace result {
using Error = hilti::rt::result::Error;
using NoResult = hilti::rt::result::NoResult;
} // namespace result

template<typename T>
using Result = hilti::rt::Result<T>;

using Nothing = hilti::rt::Nothing;

} // namespace hilti
