// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <clocale>

#include <hilti/rt/configuration.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

static void printException(const std::string& msg, const Exception& e, std::ostream& out) {
    out << "[libhilti] " << msg << " " << demangle(typeid(e).name()) << ": " << e.what() << std::endl;

    if ( e.backtrace().empty() || ! configuration::get().show_backtraces )
        return;

    out << "[libhilti] backtrace:\n";

    for ( const auto& s : e.backtrace() )
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
