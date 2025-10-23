// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <cstddef>
#include <string>
#include <utility>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Exception");

// RAII helper to set a context with a location in tests.
class TestLocation {
public:
    TestLocation(std::string location) : _location(std::move(location)) {
        _prev = context::detail::current();
        context::detail::current() = &_current;

        debug::setLocation(_location.c_str());
    }

    ~TestLocation() {
        context::detail::current() = _prev;
        debug::setLocation(nullptr);
    }

private:
    std::string _location;
    Context* _prev = nullptr;
    Context _current = Context(0);
};

TEST_CASE("construct") {
    exception::DisableAbortOnExceptions _;

    SUBCASE("global location set") {
        TestLocation loc("foo/bar");
        CHECK_EQ(to_string(Exception()), "<exception: <no error>>");
        CHECK_EQ(to_string(Exception("desc")), "<exception: desc (foo/bar)>");
        CHECK_EQ(to_string(Exception("desc", "location.h")), "<exception: desc (location.h)>");
    }

    SUBCASE("global location unset") {
        REQUIRE_EQ(debug::location(), nullptr);
        CHECK_EQ(to_string(Exception()), "<exception: <no error>>");
        CHECK_EQ(to_string(Exception("desc")), "<exception: desc>");
        CHECK_EQ(to_string(Exception("desc", "location.h")), "<exception: desc (location.h)>");
    }
}

TEST_CASE("backtrace") {
    // Frame count is hardcoded here. The backtrace should contain at least
    //
    // - one internal frame from the creation of the backtrace in `Backtrace`,
    // - two frames from doctest's expansion of `CHECK_EQ`, and
    // - one frame for the current line
    // - three frames from the test harness to reach and expand `TEST_CASE`.
#ifndef NDEBUG
#if defined(HILTI_HAVE_BACKTRACE)
    CHECK_GE(Exception("description").backtrace()->backtrace()->size(), 7U);
#endif
#else
    // No backtrace captured in release builds.
    CHECK(! Exception("description").backtrace());
#endif
}

TEST_CASE("description") {
    CHECK_EQ(Exception("description").description(), "description");
    CHECK_EQ(Exception("description", "location.h").description(), "description");
}

TEST_CASE("location") {
    CHECK_EQ(Exception("description").location(), "");
    CHECK_EQ(Exception("description", "location.h").location(), "location.h");
}

TEST_CASE("DisableAbortOnExceptions") {
    REQUIRE_FALSE(detail::globalState()->disable_abort_on_exceptions);

    {
        exception::DisableAbortOnExceptions _;
        REQUIRE(detail::globalState()->disable_abort_on_exceptions);
    }

    REQUIRE_FALSE(detail::globalState()->disable_abort_on_exceptions);
}

TEST_CASE("WouldBlock") {
    CHECK_EQ(to_string(WouldBlock("description", "location.h")), "<exception: description (location.h)>");
}

TEST_CASE("to_string") {
    CHECK_EQ(to_string(Exception("desc", "location.h")), "<exception: desc (location.h)>");
    CHECK_EQ(to_string(RuntimeError("desc", "location.h")), "<exception: desc (location.h)>");
    CHECK_EQ(to_string(FormattingError("tinyformat: from tinyformat")), "<exception: from tinyformat>");
    CHECK_EQ(to_string(WouldBlock("desc", "location.h")), "<exception: desc (location.h)>");
}

TEST_SUITE_END();
