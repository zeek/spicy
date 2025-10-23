// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/backtrace.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Backtrace");

TEST_CASE("backtrace") {
    const auto bt = Backtrace().backtrace();
    CHECK_FALSE(bt->empty());

#ifdef HILTI_HAVE_BACKTRACE
    // As the exact format of the backtrace depends on the particular platform we can only check general properties.
    CHECK(std::none_of(bt->begin(), bt->end(), [](auto& x) { return x.empty(); }));
    CHECK_GT(bt->size(), 1U); // Distinguish from case without backtrace support below.
#else
    REQUIRE_EQ(bt->size(), 1u);
    CHECK_EQ(*bt->begin(), "# <support for stack backtraces not available>");
#endif
}

// Helper function to create a backtrace with one more frame as the caller.
//
// NOTE: Some compilers remove this function even if `noinline` is given via
// e.g., constant folding, so we try to completely disable optimization.
#if defined(__clang__)
auto __attribute__((noinline, optnone)) make_backtrace() { return Backtrace(); }
#elif defined(__GNUC__)
auto __attribute__((noinline, optimize(0))) make_backtrace() { return Backtrace(); }
#else
#error "unsupported compiler"
#endif

TEST_CASE("comparison") {
    const auto bt1 = Backtrace();      // Backtrace to this call site.
    const auto bt2 = make_backtrace(); // One additional frame on top of `bt1`.

#ifdef HILTI_HAVE_BACKTRACE
    REQUIRE_EQ(bt1.backtrace()->size() + 1, bt2.backtrace()->size());
#endif

    CHECK_EQ(bt1, bt1);
    CHECK_EQ(bt2, bt2);
#ifdef HILTI_HAVE_BACKTRACE
    CHECK_NE(bt1, bt2);
    CHECK_NE(bt2, bt1);
#endif
}

TEST_CASE("demangle") {
    CHECK_EQ(demangle("i"), "int");

    // If the symbol cannot be demangled the input is returned.
    CHECK_EQ(demangle(" foobar"), " foobar");
}

TEST_SUITE_END();
