// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cxxabi.h>

#include <array>
#include <memory>
#include <string>
#include <vector>

namespace hilti::rt {

/** Captures a stack backtrace at construction time. */
class Backtrace {
public:
    Backtrace();
    Backtrace(const Backtrace& other) = default;
    Backtrace(Backtrace&& other) = default;
    ~Backtrace() = default;

    // Returns pointer to save stack space.
    std::unique_ptr<std::vector<std::string>> backtrace() const;

    friend bool operator==(const Backtrace& a, const Backtrace& b);
    friend bool operator!=(const Backtrace& a, const Backtrace& b) { return ! (a == b); }

    Backtrace& operator=(const Backtrace& other) = default;
    Backtrace& operator=(Backtrace&& other) = default;

private:
    using Callstack = std::array<void*, 32>;
    std::shared_ptr<Callstack> _callstack = nullptr;
    int _frames = -1;
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
