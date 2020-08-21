// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <functional>
#include <memory>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/global-state.h>

#include <spicy/rt/init.h>
#include <spicy/rt/parser.h>

#include "../../hilti/src/rt/tests/test_utils.h"

using hilti::rt::Bytes;
using hilti::rt::fmt;
using hilti::rt::Port;
using hilti::rt::Protocol;
using hilti::rt::to_string;
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

TEST_SUITE_END();
