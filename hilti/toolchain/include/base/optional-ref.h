// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// This was originally inspired by similar code part of
// https://github.com/Chlorie/clu, but it turned into pretty much a rewrite.
// (FWIW, that code comes with an MIT license.)

#pragma once

#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

namespace hilti {

/**
 * Similar to `std::optional<>T` but storing a reference to the wrapped
 * instance instead of a full copy. The caller must ensure that the
 * underlying instance remains valid as long as necessary.
 **/
template<typename T>
class optional_ref {
public:
    using nonConstT = typename std::remove_const<T>::type;

    optional_ref() = default;
    optional_ref(const optional_ref<T>& other) = default;
    optional_ref(optional_ref<T>&& other) noexcept = default;
    optional_ref(std::nullopt_t) {}
    optional_ref(T& other) : _ptr(&other) {}
    optional_ref(T&& other) = delete; // to avoid easy mistakes
    ~optional_ref() = default;

    bool has_value() const { return _ptr != nullptr; }

    T& value() const {
        if ( ! _ptr )
            throw std::bad_optional_access();

        return *_ptr;
    }

    T& value_or(T& default_) const { return _ptr ? *_ptr : default_; }
    void reset() { _ptr = nullptr; }

    T* operator->() const { return _ptr; }
    T& operator*() const { return *_ptr; }

    optional_ref& operator=(const optional_ref<T>& other) = default;
    optional_ref& operator=(optional_ref<T>&& other) noexcept = default;

    optional_ref& operator=(std::nullopt_t) {
        _ptr = nullptr;
        return *this;
    }

    optional_ref& operator=(T& t) {
        _ptr = &t;
        return *this;
    }

    optional_ref& operator=(T&& t) = delete; // to avoid easy mistakes

    explicit operator bool() const { return _ptr; }

    bool operator==(const optional_ref<T>& other) const {
        if ( has_value() && other.has_value() )
            return value() == other.value();

        return ! (has_value() || other.has_value());
    }

    bool operator!=(const optional_ref<T>& other) const { return ! (*this == other); }

    operator std::optional<nonConstT>() const {
        if ( has_value() )
            return value();
        else
            return std::nullopt;
    }

private:
    T* _ptr = nullptr;
};

} // namespace hilti
