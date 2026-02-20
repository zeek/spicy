// Copyright (c) 2026-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <c++/14/bits/shared_ptr_base.h>

#include <utility>

namespace hilti::rt {

// Ad-hoc non-atomic shared_ptr replacement based on libstdc++ detail classes.
//
// The overhead of a std::shared_ptr's atomic instructions is significant. With
// libstdc++ we can re-use their base classes to create a non-atomic shared_ptr.
// It's called counted_ptr.

template<typename T>
using counted_ptr = std::__shared_ptr<T, __gnu_cxx::_S_single>;

template<typename T>
using counted_weak_ptr = std::__weak_ptr<T, __gnu_cxx::_S_single>;

template<typename T>
using enable_counted_from_this = std::__enable_shared_from_this<T, __gnu_cxx::_S_single>;

template<typename T, typename... Args>
inline counted_ptr<T> make_counted(Args&&... args) {
    return std::__make_shared<T, __gnu_cxx::_S_single>(std::forward<Args>(args)...);
}
} // namespace hilti::rt
