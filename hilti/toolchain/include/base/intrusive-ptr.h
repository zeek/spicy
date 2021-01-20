// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/intrusive-ptr.h>

namespace hilti {

template<class T>
using IntrusivePtr = hilti::rt::IntrusivePtr<T>;

namespace intrusive_ptr {
using AdoptRef = ::hilti::rt::intrusive_ptr::AdoptRef;
using NewRef = ::hilti::rt::intrusive_ptr::NewRef;
using ManagedObject = ::hilti::rt::intrusive_ptr::ManagedObject;
} // namespace intrusive_ptr

template<class T, class... Ts>
IntrusivePtr<T> make_intrusive(Ts&&... args) {
    // Assumes that objects start with a reference count of 1!
    return {intrusive_ptr::AdoptRef{}, new T(std::forward<Ts>(args)...)};
}

template<class T, class U>
IntrusivePtr<T> cast_intrusive(IntrusivePtr<U> p) noexcept {
    return {intrusive_ptr::AdoptRef{}, static_cast<T*>(p.release())};
}

} // namespace hilti
