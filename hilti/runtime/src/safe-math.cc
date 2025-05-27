// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/safe-math.h>

using namespace hilti::rt;

[[noreturn]] extern void safe_math_fail(const char* msg); // defined in safe-int.cc to avoid dependency on exception.h

#define SAFE_MATH_FAIL_DEFINED
extern "C" {
#include <hilti/rt/3rdparty/SafeInt/safe_math_impl.h>
}

int64_t integer::safe_negate(uint64_t x) { return safe_sub_int64_uint64(0, x); }
