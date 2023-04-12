// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>

namespace hilti::rt {
template<typename T, typename Allocator = std::allocator<T>>
class Vector;
} // namespace hilti::rt
