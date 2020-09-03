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

    std::vector<std::string> backtrace() const;

    friend bool operator==(const Backtrace& a, const Backtrace& b);
    friend bool operator!=(const Backtrace& a, const Backtrace& b) { return ! (a == b); }

private:
    int _frames = -1;
    void* _callstack[64];
};

bool operator==(const Backtrace& a, const Backtrace& b);

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
