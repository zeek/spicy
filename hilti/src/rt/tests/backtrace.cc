// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include "base/util.h"
#include "rt/util.h"
#include <doctest/doctest.h>

#include <hilti/rt/backtrace.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Backtrace");

TEST_CASE("backtrace") {
    const auto bt = Backtrace().backtrace();
    CHECK_FALSE(bt.empty());

#ifdef HILTI_HAVE_BACKTRACE
    // As the exact format of the backtrace depends on the particular platform we can only check general properties.
    CHECK(std::none_of(bt.begin(), bt.end(), [](auto& x) { return x.empty(); }));
    CHECK_GT(bt.size(), 1u); // Distinguish from case without backtrace support below.
#else
    REQUIRE_EQ(bt.size(), 1u);
    CHECK_EQ(*bt.begin(), "# <support for stack backtraces not available>");
#endif
}

TEST_CASE("demangle") {
    CHECK_EQ(demangle("i"), "int");

    // If the symbol cannot be demangled the input is returned.
    CHECK_EQ(demangle(" foobar"), " foobar");
}

TEST_SUITE_END();
