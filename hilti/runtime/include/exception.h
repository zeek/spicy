// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <ostream>
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
 * from this. Instantiate specialized derived classes, not the base class.
 */
class Exception : public std::runtime_error {
public:
    /**
     * @param desc message describing the situation
     */
    Exception(const std::string& desc) : Exception(Internal(), "Exception", desc) {}

    /**
     * @param desc message describing the situation
     * @param location string indicating the location of the operation that failed
     */
    Exception(std::string_view desc, std::string_view location) : Exception(Internal(), "Exception", desc, location) {}

    Exception();
    Exception(const Exception&) = default;
    Exception(Exception&&) noexcept = default;
    Exception& operator=(const Exception&) = default;
    Exception& operator=(Exception&&) noexcept = default;

    // Empty, but required to make exception handling work between library
    // and host application. See:
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

protected:
    enum Internal {};

    Exception(Internal, const char* type, const std::string& desc);
    Exception(Internal, const char* type, std::string_view desc, std::string_view location);

private:
    Exception(Internal, const char* type, const std::string& what, std::string_view desc, std::string_view location);

    std::string _description;
    std::string _location;
    Backtrace _backtrace;
};

inline std::ostream& operator<<(std::ostream& stream, const Exception& e) { return stream << e.what(); }

#define HILTI_EXCEPTION(name, base)                                                                                    \
    class name : public ::hilti::rt::base {                                                                            \
    public:                                                                                                            \
        name(const std::string& desc) : base(Internal(), #name, desc) {}                                               \
        name(std::string_view desc, std::string_view location) : base(Internal(), #name, desc, location) {}            \
        virtual ~name(); /* required to create vtable, see hilti::rt::Exception */                                     \
    protected:                                                                                                         \
        using base::base;                                                                                              \
    }; // namespace hilti::rt

#define HILTI_EXCEPTION_NS(name, ns, base)                                                                             \
    class name : public ns::base {                                                                                     \
    public:                                                                                                            \
        name(const std::string& desc) : base(Internal(), #name, desc) {}                                               \
        name(std::string_view desc, std::string_view location) : base(Internal(), #name, desc, location) {}            \
        virtual ~name(); /* required to create vtable, see hilti::rt::Exception */                                     \
    protected:                                                                                                         \
        using base::base;                                                                                              \
    };

#define HILTI_EXCEPTION_IMPL(name) name::name::~name() = default;

/** Base class for exceptions thrown during runtime when encountering unexpected input/situations. */
HILTI_EXCEPTION(RuntimeError, Exception)

/** Base class for exceptions indicating non-recoverable misuse of some functionality. */
HILTI_EXCEPTION(UsageError, Exception)

/** Base class for exceptions which can be recovered. */
HILTI_EXCEPTION(RecoverableFailure, RuntimeError)

/** Thrown when an `assert` statement fails. */
HILTI_EXCEPTION(AssertionFailure, RuntimeError)

/*
 * Exception triggered y the ".?" operator to signal to host applications that
 * a struct attribute isn't set.
 */
HILTI_EXCEPTION(AttributeNotSet, RuntimeError)

/**
 * Exception triggered when a division by zero is attempted.
 */
HILTI_EXCEPTION(DivisionByZero, RuntimeError)

/** Thrown for trouble encountered while managing the runtime environment. */
HILTI_EXCEPTION(EnvironmentError, UsageError)

/** Exception indicating access to an already expired weak reference. **/
HILTI_EXCEPTION(ExpiredReference, RuntimeError)

/**
 * Exception reflecting an attempt to modify a stream object that's been frozen.
 */
HILTI_EXCEPTION(Frozen, RuntimeError)

/** Exception indicating an undefined use of a reference type. */
HILTI_EXCEPTION(IllegalReference, RuntimeError)

/** Thrown when an invalid container index is accessed. */
HILTI_EXCEPTION(IndexError, RuntimeError)

/** Exception flagging invalid arguments passed to a function. */
HILTI_EXCEPTION(InvalidArgument, RuntimeError);

/** Exception flagging access to an iterator that not, or no longer, valid. */
HILTI_EXCEPTION(InvalidIterator, RuntimeError)

/** Exception flagging incorrect use of type-info values. */
HILTI_EXCEPTION(InvalidValue, RuntimeError);

/** Exception indicating illegal reuse of MatchState. **/
HILTI_EXCEPTION(MatchStateReuse, RuntimeError)

/** Exception indicating that the request data is missing. **/
HILTI_EXCEPTION(MissingData, RecoverableFailure);

/** Exception indicating use of unsupported matching capabilities. */
HILTI_EXCEPTION(NotSupported, RuntimeError)

/** Exception indicating access to an unset (null) reference. **/
HILTI_EXCEPTION(NullReference, RuntimeError)

/** Thrown when a value is found to be outside of its permissible range. */
HILTI_EXCEPTION(OutOfRange, RuntimeError)

/**
 * Exception triggered when a numerical operation causes an overflow.
 */
HILTI_EXCEPTION(Overflow, RuntimeError)

/** Exception indicating trouble when compiling a regular expression. */
HILTI_EXCEPTION(PatternError, RuntimeError)

/** * Thrown when a default-less `switch` statement hits case that's no covered. */
HILTI_EXCEPTION(UnhandledSwitchCase, RuntimeError)

/** Exception indicating problems with UTF-8 encodings. **/
HILTI_EXCEPTION(UnicodeError, RuntimeError)

/**
 * Exception reflecting an access to an unset optional value.
 */
HILTI_EXCEPTION(UnsetOptional, RuntimeError)

/**
 * Exception triggered by member access to fields that don't hold the value.
 */
HILTI_EXCEPTION(UnsetUnionMember, RuntimeError)

/**
 * Exception triggered by the fiber code when running out of stack space.
 */
HILTI_EXCEPTION(StackSizeExceeded, RuntimeError)

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

/** Returns the message associated with an exception. This supports any C++-side exception, not just ours. */
inline std::string what(const std::exception& e) { return e.what(); }

} // namespace exception

namespace detail::adl {
inline std::string to_string(const Exception& e, adl::tag /*unused*/) { return fmt("<exception: %s>", e.what()); }
inline std::string to_string(const WouldBlock& e, adl::tag /*unused*/) { return fmt("<exception: %s>", e.what()); }
} // namespace detail::adl

} // namespace hilti::rt
