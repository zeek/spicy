// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <ostream>
#include <utility>
#include <variant>

#include <string>

#include <hilti/rt/exception.h>

namespace hilti::rt {

namespace result {

/** Represents an error message. */
class Error {
public:
    Error(std::string description = "<no description>") : _description(std::move(description)) {}
    auto& description() const { return _description; }
    operator std::string() const { return _description; }
    operator std::string_view() const { return _description; }

private:
    std::string _description;
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

/**
 * Represents either a successful result from function if it returned one, or
 * reflects an error if the function was unsuccesful.
 */
template<typename T>
class Result {
public:
    Result() : _value(result::Error("<result not initialized>")) {}

    /** Creates a successful result from a value. */
    Result(const T& t) : _value(t) {}
    /** Creates a successful result from a value. */
    Result(T&& t) : _value(std::move(t)) {}
    /** Creates an result reflecting an error. */
    Result(const result::Error& e) : _value(e) {}
    /** Creates an result reflecting an error. */
    Result(result::Error&& e) : _value(std::move(e)) {}

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
     * exception if not.
     *
     * @exception `result::NoResult` if the result reflects an error state
     */
    const T& valueOrThrow() const {
        if ( ! hasValue() )
            throw result::NoResult(error());

        return value();
    }

    /**
     * Returns the result's value if it indicates success, or throws an
     * exception if not.
     *
     * @exception `result::NoResult` if the result reflects an error state
     */
    T& valueOrThrow() {
        if ( ! hasValue() )
            throw result::NoResult(error());

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

    /** Returns true if the result represents a succesful return value. */
    bool hasValue() const { return std::holds_alternative<T>(_value); }

    /** Returns the result's value, assuming it indicates success. */
    const T& operator*() const { return value(); }
    /** Returns the result's value, assuming it indicates success. */
    T& operator*() { return value(); }
    /** Returns the result's value, assuming it indicates success. */
    const T* operator->() const { return std::get_if<T>(&_value); }
    /** Returns the result's value, assuming it indicates success. */
    T* operator->() { return std::get_if<T>(&_value); }

    /** Returns true if the result represents a succesful return value. */
    operator bool() const { return hasValue(); }

    /** Converts the result to an optional that's set if it represents a succesful return value. */
    operator std::optional<T>() const { return hasValue() ? std::make_optional(value()) : std::nullopt; }

    Result& operator=(const Result& other) = default;
    Result& operator=(Result&& other) = default; // NOLINT (hicpp-noexcept-move)

private:
    std::variant<T, result::Error> _value;
};

} // namespace hilti::rt
