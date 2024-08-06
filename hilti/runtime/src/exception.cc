// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <clocale>

#include <hilti/rt/configuration.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/profiler.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

HILTI_EXCEPTION_IMPL(RuntimeError)
HILTI_EXCEPTION_IMPL(UsageError)
HILTI_EXCEPTION_IMPL(RecoverableFailure)

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
HILTI_EXCEPTION_IMPL(MissingData)
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
    out << "[libhilti] " << msg << " " << demangle(typeid(e).name()) << ": " << e.what() << '\n';

    if ( ! configuration::get().show_backtraces )
        return;

    if ( ! e.backtrace() )
        return;

    auto bt = e.backtrace()->backtrace();
    if ( bt->empty() )
        return;

    out << "[libhilti] backtrace:\n";

    for ( const auto& s : *bt )
        out << "[libhilti]    " << s << "\n";
}

Exception::Exception(Internal, const char* type, std::string_view what, std::string_view desc,
                     std::string_view location)
    : std::runtime_error({what.data(), what.size()}), _description(desc), _location(location) {
    if ( isInitialized() )
        profiler::start(std::string("hilti/exception/") + type);

    if ( configuration::get().abort_on_exceptions && ! detail::globalState()->disable_abort_on_exceptions ) {
        // TODO(robin): This will print the name of the base class (Exception), not
        // the derived exception, because we're in the constructor. Is there
        // another way to get the final name?
        printException("Aborting on exception", *this, std::cerr);
        abort();
    }
}

Exception::Exception(Internal, const char* type, std::string_view desc)
    : Exception(Internal(), type, debug::location() ? fmt("%s (%s)", desc, debug::location()) : desc, desc,
                debug::location() ? debug::location() : "") {}

Exception::Exception(Internal, const char* type, std::string_view desc, std::string_view location)
    : Exception(Internal(), type, ! location.empty() ? fmt("%s (%s)", desc, location) : fmt("%s", desc), desc,
                location) {}

Exception::Exception() : std::runtime_error("<no error>") { /* no profiling */ }

Exception::~Exception() = default;

WouldBlock::WouldBlock(std::string_view desc, std::string_view location) : WouldBlock(fmt("%s (%s)", desc, location)) {}

exception::DisableAbortOnExceptions::DisableAbortOnExceptions() {
    detail::globalState()->disable_abort_on_exceptions++;
}

exception::DisableAbortOnExceptions::~DisableAbortOnExceptions() {
    detail::globalState()->disable_abort_on_exceptions--;
}


void exception::printUncaught(const Exception& e) { printException("Uncaught exception", e, std::cerr); }

void exception::printUncaught(const Exception& e, std::ostream& out) { printException("Uncaught exception", e, out); }
hilti::rt::FormattingError::FormattingError(std::string desc) : RuntimeError(_sanitize(std::move(desc))) {}
hilti::rt::Exception::Exception(std::string_view desc) : Exception(Internal(), "Exception", desc) {
#ifndef NDEBUG
    _backtrace = Backtrace();
#endif
}
hilti::rt::Exception::Exception(std::string_view desc, std::string_view location)
    : Exception(Internal(), "Exception", desc, location) {
#ifndef NDEBUG
    _backtrace = Backtrace();
#endif
}
hilti::rt::Exception::Exception(const Exception& other)
    : std::runtime_error(other),
      _description(other._description),
      _location(other._location),
      _backtrace(other._backtrace) {}
std::string hilti::rt::Exception::description() const { return _description; }
std::string hilti::rt::Exception::location() const { return _location; }
const hilti::rt::Backtrace* hilti::rt::Exception::backtrace() const {
    if ( ! _backtrace )
        return nullptr;

    return &*_backtrace;
}
std::ostream& hilti::rt::operator<<(std::ostream& stream, const Exception& e) { return stream << e.what(); }
std::string hilti::rt::FormattingError::_sanitize(std::string desc) {
    if ( auto pos = desc.find("tinyformat: "); pos != std::string::npos )
        desc.erase(pos, 12);

    return desc;
}
std::string hilti::rt::exception::what(const Exception& e) { return e.description(); }
std::string hilti::rt::exception::what(const std::exception& e) { return e.what(); }
std::string hilti::rt::exception::where(const Exception& e) { return e.location(); }
std::string hilti::rt::detail::adl::to_string(const Exception& e, adl::tag /*unused*/) {
    return fmt("<exception: %s>", e.what());
}
std::string hilti::rt::detail::adl::to_string(const WouldBlock& e, adl::tag /*unused*/) {
    return fmt("<exception: %s>", e.what());
}
