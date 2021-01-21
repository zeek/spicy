// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <clocale>

#include <hilti/rt/configuration.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

HILTI_EXCEPTION_IMPL(RuntimeError)
HILTI_EXCEPTION_IMPL(UserException)

HILTI_EXCEPTION_IMPL(AssertionFailure)
HILTI_EXCEPTION_IMPL(AttributeNotSet)
HILTI_EXCEPTION_IMPL(DivisionByZero)
HILTI_EXCEPTION_IMPL(EnvironmentError)
HILTI_EXCEPTION_IMPL(ExpiredReference)
HILTI_EXCEPTION_IMPL(Frozen)
HILTI_EXCEPTION_IMPL(IllegalReference)
HILTI_EXCEPTION_IMPL(IndexError)
HILTI_EXCEPTION_IMPL(InvalidArgument)
HILTI_EXCEPTION_IMPL(InvalidIterator)
HILTI_EXCEPTION_IMPL(InvalidValue)
HILTI_EXCEPTION_IMPL(MatchStateReuse)
HILTI_EXCEPTION_IMPL(NotSupported)
HILTI_EXCEPTION_IMPL(NullReference)
HILTI_EXCEPTION_IMPL(OutOfRange)
HILTI_EXCEPTION_IMPL(Overflow)
HILTI_EXCEPTION_IMPL(PatternError)
HILTI_EXCEPTION_IMPL(UnhandledSwitchCase)
HILTI_EXCEPTION_IMPL(UnicodeError)
HILTI_EXCEPTION_IMPL(UnsetOptional)
HILTI_EXCEPTION_IMPL(UnsetUnionMember)
HILTI_EXCEPTION_IMPL(StackSizeExceeded)

static void printException(const std::string& msg, const Exception& e, std::ostream& out) {
    out << "[libhilti] " << msg << " " << demangle(typeid(e).name()) << ": " << e.what() << std::endl;

    if ( ! configuration::get().show_backtraces )
        return;

    auto bt = e.backtrace();
    if ( bt->empty() )
        return;

    out << "[libhilti] backtrace:\n";

    for ( const auto& s : *bt )
        out << "[libhilti]    " << s << "\n";
}

Exception::Exception(const std::string& what, std::string_view desc, std::string_view location)
    : std::runtime_error(what), _description(desc), _location(location) {
    if ( configuration::get().abort_on_exceptions && ! detail::globalState()->disable_abort_on_exceptions ) {
        // TODO(robin): This will print the name of the base class (Exception), not
        // the derived exception, because we're in the construtor. Is there
        // another way to get the final name?
        printException("Aborting on exception", *this, std::cerr);
        abort();
    }
}

Exception::Exception(const std::string& desc)
    : Exception(debug::location() ? fmt("%s (%s)", desc, debug::location()) : desc, desc,
                debug::location() ? debug::location() : "") {}

Exception::Exception(std::string_view desc, std::string_view location)
    : Exception(fmt("%s (%s)", desc, location), desc, location) {}

Exception::~Exception() = default;

WouldBlock::WouldBlock(const std::string& desc, const std::string& location)
    : WouldBlock(fmt("%s (%s)", desc, location)) {}

exception::DisableAbortOnExceptions::DisableAbortOnExceptions() {
    detail::globalState()->disable_abort_on_exceptions++;
}

exception::DisableAbortOnExceptions::~DisableAbortOnExceptions() {
    detail::globalState()->disable_abort_on_exceptions--;
}


void exception::printUncaught(const Exception& e) { printException("Uncaught exception", e, std::cerr); }

void exception::printUncaught(const Exception& e, std::ostream& out) { printException("Uncaught exception", e, out); }
