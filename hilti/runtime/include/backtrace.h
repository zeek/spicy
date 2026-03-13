// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#if ! defined(_MSC_VER)
#include <cxxabi.h>
#endif

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
#if defined(_MSC_VER)
    // MSVC's typeid().name() returns "class X" or "struct X" prefixed names.
    if ( symbol.starts_with("class ") )
        return symbol.substr(6);
    if ( symbol.starts_with("struct ") )
        return symbol.substr(7);
    if ( symbol.starts_with("enum ") )
        return symbol.substr(5);
    return symbol;
#else
    int status;
    char* dname = abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, &status);
    std::string x = (dname && status == 0) ? dname : symbol;
    if ( dname )
        free(dname); // NOLINT

    return x;
#endif
}

} // namespace hilti::rt
