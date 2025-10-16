// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <compare>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/null.h>

namespace hilti::rt {

namespace optional {

/**
 * Special exception reflecting an access to an optional that's unset, without
 * that being a runtime error condition. This is thrown (only) by
 * ``Optional::tryValue()``.
 */
struct Unset : public std::exception {};

namespace detail {
extern __attribute__((noreturn)) void throw_unset();          // throws rt::optional::Unset
extern __attribute__((noreturn)) void throw_unset_optional(); // throws rt::UnsetOptional
} // namespace detail
} // namespace optional

template<typename T>
class Optional : protected std::optional<T> {
public:
    using value_type = T;

    /** Default constructor creating an unset optional. */
    constexpr Optional() = default;

    /** Constructor from value creating a set optional. */
    constexpr Optional(const T& v) : std::optional<T>(v) {}

    /** Constructor from r-value creating a set optional. */
    constexpr Optional(T&& v) : std::optional<T>(std::move(v)) {}

    /** Copy constructor. */
    Optional(const Optional&) = default;

    /** Move constructor. */
    Optional(Optional&&) noexcept = default;

    /** Constructor from null value creating an unset optional. */
    constexpr Optional(hilti::rt::Null) noexcept {}

    /** In-place constructor forwarding arguments to T's constructor. */
    constexpr Optional(std::in_place_t, auto&&... args)
        : std::optional<T>(std::in_place, std::forward<decltype(args)>(args)...) {}

    /**
     * Constructor from a value of different type U that's convertible to T.
     */
    template<typename U>
    constexpr Optional(U&& v)
        requires(std::is_constructible_v<T, U> && ! std::is_same_v<std::decay_t<U>, Optional> &&
                 ! std::is_same_v<std::decay_t<U>, T>)
        : std::optional<T>(std::forward<U>(v)) {}

    /**
     * Constructor from different optional type containing a value of type U
     * that's convertible to T.
     */
    template<typename U>
    Optional(Optional<U>&& v)
        requires(! std::is_same_v<U, T> && std::is_constructible_v<T, U>)
    {
        if ( v )
            std::optional<T>::emplace(std::move(v).value());
    }

    /** Destructor. */
    ~Optional() = default;

    /** Returns true if the optional is set. */
    auto hasValue() const noexcept { return std::optional<T>::has_value(); }

    /**
     * Returns the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    const T& value() const& {
        if ( hasValue() )
            return std::optional<T>::value();
        else
            optional::detail::throw_unset_optional();
    }

    /**
     * Returns the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    T& value() & {
        if ( hasValue() )
            return std::optional<T>::value();
        else
            optional::detail::throw_unset_optional();
    }

    /**
     * Returns the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    T&& value() && {
        if ( hasValue() )
            return std::move(std::optional<T>::value());
        else
            optional::detail::throw_unset_optional();
    }

    /**
     * Returns the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    const T&& value() const&& {
        if ( hasValue() )
            return std::move(std::optional<T>::value());
        else
            optional::detail::throw_unset_optional();
    }

    /**
     * Returns the contained value or throws `optional::Unset` if not set.
     *
     * Note that this method differs from `value()` in that it throws a
     * different exception that's not derived from `RuntimeError`. This is for
     * catching accesses to a unset optional that are deemed legitimate within
     * the caller's context.
     */
    const auto& tryValue() const {
        if ( hasValue() )
            return std::optional<T>::value();
        else
            optional::detail::throw_unset();
    }

    /** Returns the contained value or a default if not set. */
    auto valueOr(const T& default_) const& { return hasValue() ? std::optional<T>::value() : default_; }

    /**
     * Returns the contained value, potentially first initializing it with a
     * default if not already set.
     *
     * @param default_ the default value to initialize with if not set yet
     */
    auto& valueOrInit(T&& default_) {
        if ( ! hasValue() )
            std::optional<T>::emplace(std::move(default_));

        return std::optional<T>::value();
    }

    /**
     * Returns the contained value, potentially first initializing it with a
     * default-constructed value if not already set.
     */
    auto& valueOrInit() {
        if ( ! hasValue() )
            std::optional<T>::emplace();

        return std::optional<T>::value();
    }

    // Methods of `std::optional`.
    using std::optional<T>::emplace;
    using std::optional<T>::reset;
    using std::optional<T>::swap;
    using std::optional<T>::operator bool;

    /**
     * Returns the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    const T& operator*() const& { return value(); }

    /**
     * Returns the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    T& operator*() & { return value(); }

    /**
     * Returns the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    T&& operator*() && { return std::move(value()); }

    /**
     * Returns the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    const T&& operator*() const&& { return std::move(value()); }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    const T* operator->() const& { return std::addressof(value()); }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    T* operator->() & { return std::addressof(value()); }

    /**
     * Returns a pointer to the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    const T* operator->() const&& = delete;

    /**
     * Returns a pointer to the contained value.
     *
     * @throws optional::Unset if the optional is not set.
     */
    T* operator->() && = delete;

    /** Copy assignment operator. */
    Optional& operator=(const Optional&) = default;

    /** Move assignment operator. */
    Optional& operator=(Optional&&) noexcept = default;

    /** Assigns from null value, resetting the optional. */
    Optional& operator=(hilti::rt::Null) noexcept {
        reset();
        return *this;
    }

    /** Assigns from a value of different type U that's convertible to T. */
    template<typename U>
    Optional& operator=(U&& v) // NOLINT(misc-unconventional-assign-operator) false positive
        requires(! std::is_same_v<std::decay_t<U>, Optional> && std::is_constructible_v<T, U>)
    {
        std::optional<T>::emplace(std::forward<U>(v));
        return *this;
    }

    /**
     * Assigns from a value of different optional type containing a value of
     * type U that's convertible to T.
     */
    template<typename U>
    Optional& operator=(const Optional<U>& v)
        requires(! std::is_same_v<U, T> && std::is_constructible_v<T, const U&>)
    {
        if ( v )
            std::optional<T>::emplace(v.value());
        else
            reset();

        return *this;
    }

    /**
     * Assigns from a different optional type containing a value of type U
     * that's convertible to T.
     */
    template<typename U>
    Optional& operator=(Optional<U>&& v)
        requires(! std::is_same_v<U, T> && std::is_constructible_v<T, U>)
    {
        if ( v )
            std::optional<T>::emplace(std::move(v).value());
        else
            reset();

        return *this;
    }

    template<typename U>
    constexpr bool operator==(const Optional<U>& other) const {
        if ( ! hasValue() && ! other.hasValue() )
            return true;

        if ( ! hasValue() || ! other.hasValue() )
            return false;

        return value() == other.value();
    }

    template<typename U>
    constexpr bool operator!=(const Optional<U>& other) const {
        return ! (*this == other);
    }

    template<typename U>
    constexpr auto operator<(const Optional<U>& other) const {
        if ( ! hasValue() && ! other.hasValue() )
            return false;

        if ( ! hasValue() )
            return true;

        if ( ! other.hasValue() )
            return false;

        return value() < other.value();
    }

    constexpr bool operator==(hilti::rt::Null) const noexcept { return ! hasValue(); }
    constexpr bool operator!=(hilti::rt::Null) const noexcept { return hasValue(); }
};

namespace detail::adl {
template<typename T>
inline std::string to_string(const Optional<T>& x, adl::tag /*unused*/) {
    return x ? hilti::rt::to_string(*x) : "(not set)";
}

} // namespace detail::adl

namespace optional {

/**
 * Constructs an optional initialized to a given value. This is similar to
 * ``std::make_optional``.
 */
template<class T>
constexpr Optional<std::decay_t<T>> make(T&& v) {
    return Optional<std::decay_t<T>>(std::forward<T>(v));
}

/**
 * Constructs an optional initialized to a value constructed from given
 * arguments. This is similar to ``std::make_optional``.
 */
template<class T, class... Args>
constexpr Optional<T> make(Args&&... args) {
    return Optional<T>(std::in_place, std::forward<Args>(args)...);
}

} // namespace optional

template<>
inline std::string detail::to_string_for_print<Optional<std::string>>(const Optional<std::string>& x) {
    return x ? *x : "(not set)";
}

template<>
inline std::string detail::to_string_for_print<Optional<std::string_view>>(const Optional<std::string_view>& x) {
    return x ? std::string(*x) : "(not set)";
}

} // namespace hilti::rt

namespace std {

template<typename T>
std::ostream& operator<<(std::ostream& out, const hilti::rt::Optional<T>& x) {
    return out << ::hilti::rt::to_string(x);
}

template<typename T>
struct hash<hilti::rt::Optional<T>> {
    size_t operator()(const hilti::rt::Optional<T>& opt) const noexcept {
        if ( opt.hasValue() )
            return std::hash<T>{}(opt.value());
        else
            return 0;
    }
};

} // namespace std
