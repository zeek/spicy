// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cxxabi.h>

#include <string>
#include <vector>

namespace hilti::rt {

/** Captures a stack backtrace at construction time. */
class Backtrace {
public:
    Backtrace();

    const auto& backtrace() const { return _backtrace; }

    friend bool operator==(const Backtrace& a, const Backtrace& b) { return a._backtrace == b._backtrace; }
    friend bool operator!=(const Backtrace& a, const Backtrace& b) { return ! (a == b); }

private:
    std::vector<std::string> _backtrace;
};

/** Wrapper around the ABI's C++ demangle function. */
inline std::string demangle(const std::string& symbol) {
    int status;
    char* dname = abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, &status);
    std::string x = (dname && status == 0) ? dname : symbol;
    if ( dname )
        free(dname); // NOLINT

    return x;
}

} // namespace hilti::rt
