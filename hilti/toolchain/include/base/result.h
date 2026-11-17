// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/result.h>

namespace hilti {
namespace result {
using hilti::rt::result::Error;
using hilti::rt::result::NoResult;
} // namespace result

template<typename T>
using Result = hilti::rt::Result<T>;

using hilti::rt::Nothing;

} // namespace hilti
