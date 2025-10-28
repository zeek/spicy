// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <ostream>
#include <string>
#include <utility>
#include <variant>

#include <hilti/rt/exception.h>
#include <hilti/rt/types/optional.h>

namespace hilti::rt {

namespace result {

/** Represents an error message. */
class Error {
public:
    Error(std::string description = "<no description>", std::string context = "")
        : _description(std::move(description)), _context(std::move(context)) {}
    const auto& description() const { return _description; }
    const auto& context() const { return _context; }
    operator std::string() const { return _description; }
    operator std::string_view() const { return _description; }

private:
    std::string _description;
    std::string _context;
};

inline std::ostream& operator<<(std::ostream& out, const Error& error) {
    out << error.description();
    return out;
}

inline bool operator==(const Error& a, const Error& b) { return a.description() == b.description(); }
inline bool operator!=(const Error& a, const Error& b) { return ! (a == b); }

/** Exception indicating that no result is available if though one was requested. */
class NoResult : public RuntimeError {
public:
    NoResult(Error err) : RuntimeError(err.description()), _error(std::move(err)) {}

private:
    Error _error;
};

/** Exception indicating that no error has been reported if though one was expected to be available. */
class NoError : public RuntimeError {
public:
    NoError() : RuntimeError("<no error>") {}
};

} // namespace result

struct Nothing {};

inline bool operator==(const Nothing&, const Nothing&) { return true; }
inline bool operator!=(const Nothing&, const Nothing&) { return false; }

namespace detail::adl {
inline std::string to_string(const Nothing& n, adl::tag /*unused*/) { return "<nothing>"; };
} // namespace detail::adl

/**
 * Represents either a successful result from function if it returned one, or
 * reflects an error if the function was unsuccessful.
 */
template<typename T>
class Result {
public:
    Result() : _value(std::in_place_type_t<result::Error>(), result::Error("<result not initialized>")) {}

    /** Creates a successful result from a value. */
    Result(const T& t) : _value(std::in_place_type_t<T>(), t) {}
    /** Creates a successful result from a value. */
    Result(T&& t) : _value(std::in_place_type_t<T>(), std::move(t)) {}
    /** Creates an result reflecting an error. */
    Result(const result::Error& e) : _value(std::in_place_type_t<result::Error>(), e) {}
    /** Creates an result reflecting an error. */
    Result(result::Error&& e) : _value(std::in_place_type_t<result::Error>(), std::move(e)) {}

    Result(const Result& o) = default;
    Result(Result&& o) = default; // NOLINT (hicpp-noexcept-move)
    ~Result() = default;

    /**
     * Returns the result's value, assuming it indicates success.
     *
     * @exception `std::bad_variant_access` if the result reflects an error
     * state
     */
    const T& value() const { return std::get<T>(_value); }

    /**
     * Returns the result's value, assuming it indicates success.
     *
     * @exception `std::bad_variant_access` if the result reflects an error
     * state
     */
    T& value() { return std::get<T>(_value); }

    /**
     * Returns the result's value if it indicates success, or throws an
     * exception if not. By default, the exception thrown is `result::NoResult`.
     *
     * @tparam E type of the exception to throw
     * @exception exception of type `E` if the result reflects an error state
     */
    template<typename E = result::NoResult>
    const T& valueOrThrow() const {
        if ( ! hasValue() )
            throw E(error());

        return value();
    }

    /**
     * Returns the result's value if it indicates success, or throws an
     * exception if not.
     *
     * @tparam E type of the exception to throw
     * @exception exception of type `E` if the result reflects an error state
     */
    template<typename E = result::NoResult>
    T& valueOrThrow() {
        if ( ! hasValue() )
            throw E(error());

        return value();
    }

    /**
     * Returns the result's error, assuming it reflect one.
     *
     * @exception `std::bad_variant_access` if the result doe not reflect an error
     * state
     */
    const result::Error& error() const { return std::get<result::Error>(_value); }

    /**
     * Returns the result's error if it indicates failure, or throws an
     * exception if not.
     *
     * @exception `result::NoError` if the result does not reflect an error state
     */
    const result::Error& errorOrThrow() const {
        if ( hasValue() )
            throw result::NoError();

        return error();
    }

    /** Returns true if the result represents a successful return value. */
    bool hasValue() const { return std::holds_alternative<T>(_value); }

    /** Returns the result's value, assuming it indicates success. */
    const T& operator*() const { return value(); }
    /** Returns the result's value, assuming it indicates success. */
    T& operator*() { return value(); }
    /** Returns the result's value, assuming it indicates success. */
    const T* operator->() const { return std::get_if<T>(&_value); }
    /** Returns the result's value, assuming it indicates success. */
    T* operator->() { return std::get_if<T>(&_value); }

    /** Returns true if the result represents a successful return value. */
    explicit operator bool() const { return hasValue(); }

    Result& operator=(const Result& other) = default;
    Result& operator=(Result&& other) = default; // NOLINT (hicpp-noexcept-move)

    friend bool operator==(const Result& a, const Result& b) {
        if ( a.hasValue() != b.hasValue() )
            return false;

        if ( a.hasValue() )
            return a.value() == b.value();
        else
            return a.error() == b.error();
    }

    friend bool operator!=(const Result& a, const Result& b) { return ! (a == b); }

private:
    std::variant<T, result::Error> _value;
};

/** Similar to `std::make_optional`, construct a result from a value. */
template<typename T>
Result<T> make_result(T&& t) {
    return Result<T>(std::forward<T>(t));
}

} // namespace hilti::rt
