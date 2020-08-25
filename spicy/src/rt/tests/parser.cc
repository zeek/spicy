// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/types/vector.h>

#include <spicy/rt/filter.h>
#include <spicy/rt/init.h>
#include <spicy/rt/parser.h>
#include <spicy/rt/typedefs.h>

#include "../../hilti/src/rt/tests/test_utils.h"

using hilti::rt::Bytes;
using hilti::rt::fmt;
using hilti::rt::Port;
using hilti::rt::Protocol;
using hilti::rt::to_string;
using hilti::rt::Vector;
using namespace hilti::rt::bytes::literals;
using namespace spicy::rt;

TEST_SUITE_BEGIN("Parser");

TEST_CASE("Direction") {
    CHECK_EQ(to_string(Direction::Originator), "originator");
    CHECK_EQ(to_string(Direction::Responder), "responder");
    CHECK_EQ(to_string(Direction::Both), "both");
    CHECK_EQ(to_string(Direction::Undef), "undefined");

    CHECK_EQ(fmt("%s", Direction::Originator), "originator");
    CHECK_EQ(fmt("%s", Direction::Responder), "responder");
    CHECK_EQ(fmt("%s", Direction::Both), "both");
    CHECK_EQ(fmt("%s", Direction::Undef), "undefined");
}

TEST_CASE("ParserPort") {
    CHECK_EQ(to_string(ParserPort({Port(80, Protocol::TCP), Direction::Originator})), "80/tcp (originator direction)");
    CHECK_EQ(to_string(ParserPort({Port(80, Protocol::TCP), Direction::Both})), "80/tcp");

    CHECK_EQ(fmt("%s", ParserPort({Port(80, Protocol::TCP), Direction::Originator})), "80/tcp (originator direction)");
    CHECK_EQ(fmt("%s", ParserPort({Port(80, Protocol::TCP), Direction::Both})), "80/tcp");
}

struct UnitWithSinkSupport : std::enable_shared_from_this<UnitWithSinkSupport> {
    static Parser __parser;
    sink::detail::State* __sink = nullptr;
    std::function<void(uint64_t, uint64_t)> __on_0x25_gap = nullptr;
    std::function<void(uint64_t)> __on_0x25_skipped = nullptr;
    std::function<void(uint64_t, const Bytes&, const Bytes&)> __on_0x25_overlap = nullptr;
    std::function<void(uint64_t, const Bytes&)> __on_0x25_undelivered = nullptr;

    UnitWithSinkSupport& operator=(const UnitWithSinkSupport&) {
        // Not implemented.
        return *this;
    }
};

Parser UnitWithSinkSupport::__parser{};

TEST_CASE("registerParser") {
    hilti::rt::test::CaptureIO _(std::cerr); // Suppress output.

    SUBCASE("w/o sink support") {
        done(); // Ensure no parsers are registered, yet.
        REQUIRE(detail::globalState()->parsers.empty());

        Parser parser;
        parser.mime_types = {MIMEType("foo/bar"), MIMEType("foo/*")};
        REQUIRE_FALSE(parser.__parse_sink);
        REQUIRE_FALSE(parser.__hook_gap);
        REQUIRE_FALSE(parser.__hook_skipped);
        REQUIRE_FALSE(parser.__hook_undelivered);

        detail::registerParser(parser, UnitRef<int>());

        REQUIRE_EQ(detail::globalState()->parsers.size(), 1u);
        CHECK_EQ(detail::globalState()->parsers.at(0), &parser);
        CHECK(detail::globalState()->parsers_by_name.empty()); // Never updated.
        CHECK_EQ(detail::globalState()->parsers_by_mime_type,
                 std::map<std::string, std::vector<const Parser*>>({{"foo/bar", {&parser}}, {"foo", {&parser}}}));

        CHECK_FALSE(parser.__parse_sink);
        CHECK_FALSE(parser.__hook_gap);
        CHECK_FALSE(parser.__hook_skipped);
        CHECK_FALSE(parser.__hook_undelivered);
    }

    SUBCASE("w/ sink support") {
        done(); // Ensure no parsers are registered, yet.
        REQUIRE(detail::globalState()->parsers.empty());

        Parser parser;
        parser.mime_types = {MIMEType("foo/bar"), MIMEType("foo/*")};
        REQUIRE_FALSE(parser.__parse_sink);
        REQUIRE_FALSE(parser.__hook_gap);
        REQUIRE_FALSE(parser.__hook_skipped);
        REQUIRE_FALSE(parser.__hook_undelivered);

        detail::registerParser(parser, UnitRef<UnitWithSinkSupport>());

        REQUIRE_EQ(detail::globalState()->parsers.size(), 1u);
        CHECK_EQ(detail::globalState()->parsers.at(0), &parser);
        CHECK(detail::globalState()->parsers_by_name.empty()); // Never updated.
        CHECK_EQ(detail::globalState()->parsers_by_mime_type,
                 std::map<std::string, std::vector<const Parser*>>({{"foo/bar", {&parser}}, {"foo", {&parser}}}));

        CHECK(parser.__parse_sink);
        CHECK(parser.__hook_gap);
        CHECK(parser.__hook_skipped);
        CHECK(parser.__hook_undelivered);
    }
}

TEST_CASE("waitForInput") {
    hilti::rt::test::CaptureIO _(std::cerr); // Suppress output.

    hilti::rt::init(); // Noop if already initialized.

    auto data = hilti::rt::ValueReference<hilti::rt::Stream>();
    auto view = data->view();

    auto filters = hilti::rt::StrongReference<filter::detail::Filters>();

    auto _waitForInput = [&](hilti::rt::resumable::Handle*) {
        return detail::waitForInput(data, view, "error message", "location", filters);
    };

    auto waitForInput = [&]() { return hilti::rt::fiber::execute(_waitForInput); };

    SUBCASE("not enough data") {
        // `waitForInput` yields if not enough data available. We
        // can only wait from inside a `Resumable`.
        CHECK_FALSE(waitForInput());
        CHECK_THROWS_WITH_AS(_waitForInput(nullptr), "'yield' in non-suspendable context",
                             const hilti::rt::RuntimeError&);
    }

    SUBCASE("enough data") {
        auto res = waitForInput();
        CHECK_FALSE(res);
        data->append("\x01\x02\x03"_b);
        res.resume();
        CHECK(res);
    }

    SUBCASE("eod") {
        data->freeze();
        CHECK_THROWS_WITH_AS(waitForInput(), "parse error: error message (location)", const ParseError&);
    }
}

TEST_CASE("waitForInputOrEod with min") {
    hilti::rt::test::CaptureIO _(std::cerr); // Suppress output.

    // Reinitialize the runtime to make sure we do not carry over state between test cases.
    //
    // TODO(robin): If we comment out this `done` the "enough data" test cases fails. This seems weird.
    hilti::rt::done();
    hilti::rt::init();

    auto data = hilti::rt::ValueReference<hilti::rt::Stream>();
    auto view = data->view();

    auto filters = hilti::rt::StrongReference<filter::detail::Filters>();

    auto _waitForInputOrEod = [&](hilti::rt::resumable::Handle*) {
        return detail::waitForInputOrEod(data, view, 3, filters);
    };

    auto waitForInputOrEod = [&]() { return hilti::rt::fiber::execute(_waitForInputOrEod); };

    SUBCASE("wait for nothing") {
        // We can always successfully get "no data".
        CHECK(detail::waitForInputOrEod(data, data->view(), 0, filters));
    }

    SUBCASE("not enough data") {
        // `waitForInputOrEod` yields if not enough data is available. We
        // can only wait from inside a `Resumable`.
        CHECK_FALSE(waitForInputOrEod());
        CHECK_THROWS_WITH_AS(_waitForInputOrEod(nullptr), "'yield' in non-suspendable context",
                             const hilti::rt::RuntimeError&);
    }

    SUBCASE("enough data") {
        // With enough data available we can get a result.
        data->append("\x01\x02"_b);
        REQUIRE_EQ(data->size(), 2);
        CHECK_FALSE(waitForInputOrEod()); // Still need one more byte.

        data->append("\x03");
        REQUIRE_EQ(data->size(), 3);
        const auto res = waitForInputOrEod();
        REQUIRE(res);
        CHECK(res.get<bool>());
    }

    SUBCASE("eod") {
        data->freeze();
        const auto res = waitForInputOrEod();
        REQUIRE(res);
        CHECK_FALSE(res.get<bool>());
    }

    SUBCASE("with filters") {
        SUBCASE("empty filter list") {
            filters = Vector<filter::detail::OneFilter>();

            // Append enough data so this call would succeed if no filter was present.
            data->append("\x01\x02\x03"_b);
            REQUIRE_EQ(data->size(), 3);

            // No filter present so we can get the available data directly.
            const auto res = waitForInputOrEod();
            REQUIRE(res);
            CHECK(res.get<bool>());
        }

        SUBCASE("multiple filters") {
            filters = Vector<filter::detail::OneFilter>();

            bool called1 = false;
            bool called2 = false;

            filters->push_back(
                filter::detail::OneFilter({.resumable = [&](hilti::rt::resumable::Handle*) { called1 = true; }}));
            filters->push_back(
                filter::detail::OneFilter({.resumable = [&](hilti::rt::resumable::Handle*) { called2 = true; }}));

            REQUIRE_FALSE(called1);

            // We trigger waiting for input with not enough data available and
            // resume later as `waitForInputOrEod` would short-circuit were
            // enough data available initally.
            auto res = waitForInputOrEod();
            data->append("\x01\x02\x03"_b);
            res.resume();

            CHECK(res);
            CHECK(called1);
            CHECK(called2);
        }
    }
}

TEST_SUITE_END();
