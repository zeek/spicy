// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/backtrace.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>

namespace hilti::rt {

/**
 * HILTI's base exception type. All HILTI-side runtime exceptions are derived
 * from this.
 */
class Exception : public std::runtime_error {
public:
    /**
     * @param desc message describing the situation
     */
    Exception(const std::string& desc);

    /**
     * @param desc message describing the situation
     * @param location string indicating the location of the operation that failed
     */
    Exception(std::string_view desc, std::string_view location);

    Exception() : std::runtime_error("<no error>"){};
    Exception(const Exception&) = default;
    Exception(Exception&&) noexcept = default;
    Exception& operator=(const Exception&) = default;
    Exception& operator=(Exception&&) noexcept = default;

    // Empty, but necessary to make exception handling work between library
    // and host application. Presumably this:
    // http://www.toptip.ca/2012/06/c-exceptions-thrown-from-shared-library.html
    ~Exception() override;

    /** Returns the message associated with the exception. */
    auto description() const { return _description; }

    /** Returns the location associated with the exception. */
    auto location() const { return _location; }

    /**
     * Returns a stack backtrace captured at the time the exception was
     * thrown.
     */
    auto backtrace() const { return _backtrace.backtrace(); }

private:
    Exception(const std::string& what, std::string_view desc, std::string_view location);

    std::string _description;
    std::string _location;
    Backtrace _backtrace;
};

#define HILTI_EXCEPTION(name, base)                                                                                    \
    class name : public base {                                                                                         \
    public:                                                                                                            \
        using base::base;                                                                                              \
    };

#define HILTI_EXCEPTION_NS(name, ns, base)                                                                             \
    class name : public ns::base {                                                                                     \
    public:                                                                                                            \
        using ns::base::base;                                                                                          \
    };

/** Base class for exceptions thrown by the runtime system. */
HILTI_EXCEPTION(RuntimeError, Exception)

/** Base class for exceptions created by HILTI programs. */
HILTI_EXCEPTION(UserException, Exception)

/** Thrown for trouble encountered while managing the runtime environment. */
HILTI_EXCEPTION(EnvironmentError, Exception)

/** Thrown when an `assert` statement fails. */
HILTI_EXCEPTION(AssertionFailure, RuntimeError)

/** Thrown when an invalid container index is accessed. */
HILTI_EXCEPTION(IndexError, RuntimeError)

/** * Thrown when a default-less `switch` statement hits case that's no covered. */
HILTI_EXCEPTION(UnhandledSwitchCase, RuntimeError)

/** Thrown when a value is found to be outside of its permissible range. */
HILTI_EXCEPTION(OutOfRange, RuntimeError)

/** Exception flagging invalid arguments passed to a function. */
HILTI_EXCEPTION(InvalidArgument, RuntimeError);

/** Thrown when fmt() reports a problem. */
class FormattingError : public RuntimeError {
public:
    FormattingError(std::string desc) : RuntimeError(_sanitize(std::move(desc))) {}

private:
    std::string _sanitize(std::string desc) {
        if ( auto pos = desc.find("tinyformat: "); pos != std::string::npos )
            desc.erase(pos, 12);

        return desc;
    }
};

/**
 * Exception signaling that an operation could not complete due to lack of
 * input or I/O delays. The operation should be retried when that situation
 * may have changed.
 *
 * This is outside the standard exception hierarchy as it does not reflect an
 * error condition.
 */
class WouldBlock : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;

    /**
     * @param desc message describing the situation
     * @param location string indicating the location of the operation that couldn't complete
     */
    WouldBlock(const std::string& desc, const std::string& location);
};

namespace exception {

// Disables `Configuration::abort_on_exception` during its lifetime.
class DisableAbortOnExceptions {
public:
    DisableAbortOnExceptions();
    ~DisableAbortOnExceptions();

    DisableAbortOnExceptions(const DisableAbortOnExceptions&) = delete;
    DisableAbortOnExceptions(DisableAbortOnExceptions&&) noexcept = delete;
    DisableAbortOnExceptions& operator=(const DisableAbortOnExceptions&) = delete;
    DisableAbortOnExceptions& operator=(DisableAbortOnExceptions&&) noexcept = delete;
};

/** Utility function printing out an uncaught exception to stderr. */
void printUncaught(const Exception& e);

/** Utility function printing out an uncaught exception to an output stream. */
void printUncaught(const Exception& e, std::ostream& out);
} // namespace exception

namespace detail::adl {
inline std::string to_string(const Exception& e, adl::tag /*unused*/) { return fmt("<exception: %s>", e.what()); }
} // namespace detail::adl

} // namespace hilti::rt
