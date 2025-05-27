// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/exception.h>
#include <hilti/rt/safe-int.h>

using namespace hilti::rt;

void hilti::rt::integer::detail::SafeIntException::SafeIntOnOverflow() { throw Overflow("integer overflow"); }

void hilti::rt::integer::detail::SafeIntException::SafeIntOnDivZero() {
    throw DivisionByZero("integer division by zero");
}

void safe_math_fail(const char* msg) { throw OutOfRange("integer value out of range"); } // NOLINT
