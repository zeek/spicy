// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

// Use a non-atomic refcount for shared_ptr.
#define BOOST_SP_DISABLE_THREADS

#include <utility>

#include <hilti/rt/3rdparty/boost/enable_shared_from_this.hpp> // IWYU pragma: export
#include <hilti/rt/3rdparty/boost/smart_ptr/bad_weak_ptr.hpp>  // IWYU pragma: export
#include <hilti/rt/3rdparty/boost/smart_ptr/make_shared.hpp>   // IWYU pragma: export
#include <hilti/rt/3rdparty/boost/smart_ptr/shared_ptr.hpp>    // IWYU pragma: export
#include <hilti/rt/3rdparty/boost/smart_ptr/weak_ptr.hpp>      // IWYU pragma: export

namespace hilti::rt {
template<typename T>
using WeakPtr = boost::weak_ptr<T>;

template<typename T>
using SharedPtr = boost::shared_ptr<T>;

template<typename T>
using EnableSharedFromThis = boost::enable_shared_from_this<T>;

using BadWeakPtr = boost::bad_weak_ptr;

template<typename T, typename... Args>
auto makeShared(Args&&... args) {
    return boost::make_shared<T>(std::forward<Args>(args)...);
}

template<class T, class U>
auto staticPointerCast(const SharedPtr<U>& r) noexcept {
    return boost::static_pointer_cast<T>(r);
}
} // namespace hilti::rt
