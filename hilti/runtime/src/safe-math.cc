// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/exception.h>
#include <hilti/rt/safe-math.h>

using namespace hilti::rt;

[[noreturn]] inline static void safe_math_fail(const char* /*msg*/) { throw OutOfRange("integer value out of range"); }

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

#define SAFE_MATH_FAIL_DEFINED
extern "C" {
#include <hilti/rt/3rdparty/SafeInt/safe_math_impl.h>
}

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

int64_t integer::safe_negate(uint64_t x) { return safe_sub_int64_uint64(0, x); }
