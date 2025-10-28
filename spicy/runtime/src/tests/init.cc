// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <map>
#include <vector>

#include <hilti/rt/init.h>
#include <hilti/rt/types/port.h>

#include <spicy/rt/global-state.h>
#include <spicy/rt/init.h>
#include <spicy/rt/mime.h>
#include <spicy/rt/parser.h>
#include <spicy/rt/typedefs.h>

using namespace spicy::rt;

TEST_SUITE_BEGIN("Init");

TEST_CASE("init") {
    done(); // Noop if not initialized.
    CHECK_EQ(detail::__global_state, nullptr);

    hilti::rt::init(); // Noop if already initialized.

    SUBCASE("w/o parser setup") {
        init();

        const auto* gs = detail::__global_state;
        REQUIRE_NE(gs, nullptr);
        CHECK(gs->runtime_is_initialized);
        CHECK_EQ(gs->default_parser, static_cast<hilti::rt::Optional<const Parser*>>(hilti::rt::Null()));
        CHECK(gs->parsers_by_name.empty());
        CHECK(gs->parsers_by_mime_type.empty());

        init();

        CHECK_EQ(detail::__global_state, gs);
    }

    SUBCASE("single parser") {
        const Parser parser("Parser", true, Parse1Function(), Parse2Function<int>(), Parse3Function(), nullptr, nullptr,
                            "Parser: description", {MIMEType("foo/bar")},
                            {ParserPort{hilti::rt::tuple::make(hilti::rt::Port(4040, hilti::rt::Protocol::TCP),
                                                               Direction::Both)}});
        detail::globalState()->parsers.emplace_back(&parser);

        init();

        const auto* gs = detail::__global_state;
        REQUIRE_NE(gs, nullptr);
        CHECK_EQ(*gs->default_parser, &parser);

        CHECK_EQ(gs->parsers_by_name, std::map<std::string, std::vector<const Parser*>>(
                                          {{{parser.name.data(), parser.name.size()}, {&parser}},
                                           {"4040/tcp", {&parser}},
                                           {"4040/tcp%orig", {&parser}},
                                           {"4040/tcp%resp", {&parser}},
                                           {parser.mime_types.at(0), {&parser}}}));
        CHECK_EQ(gs->parsers_by_mime_type,
                 std::map<std::string, std::vector<const Parser*>>({{parser.mime_types.at(0), {&parser}}}));
    }

    SUBCASE("multiple parsers, all 'public'") {
        const Parser parser1("Parser1", true, Parse1Function(), Parse2Function<int>(), Parse3Function(), nullptr,
                             nullptr, "Parser1: description", {MIMEType("foo/bar")},
                             {ParserPort{hilti::rt::tuple::make(hilti::rt::Port(4040, hilti::rt::Protocol::TCP),
                                                                Direction::Originator)}});
        const Parser parser2("Parser2", true, Parse1Function(), Parse2Function<int>(), Parse3Function(), nullptr,
                             nullptr, "Parser2: description", {MIMEType("foo/*")},
                             {ParserPort{hilti::rt::tuple::make(hilti::rt::Port(4040, hilti::rt::Protocol::TCP),
                                                                Direction::Responder)}});
        detail::globalState()->parsers.emplace_back(&parser1);
        detail::globalState()->parsers.emplace_back(&parser2);

        init();

        const auto* gs = detail::__global_state;
        REQUIRE_NE(gs, nullptr);

        // No default parser possible since all parsers `public`.
        CHECK_EQ(gs->default_parser, hilti::rt::Optional<const Parser*>(hilti::rt::Null()));

        CAPTURE(gs->parsers.size());
        CAPTURE(gs->parsers_by_name.size());
        CHECK_EQ(gs->parsers_by_name, std::map<std::string, std::vector<const Parser*>>(
                                          {{{parser1.name.data(), parser1.name.size()}, {&parser1}},
                                           {"4040/tcp%orig", {&parser1}},
                                           {parser1.mime_types.at(0), {&parser1}},
                                           {{parser2.name.data(), parser2.name.size()}, {&parser2}},
                                           {"4040/tcp%resp", {&parser2}}}));
        CHECK_EQ(gs->parsers_by_mime_type,
                 std::map<std::string, std::vector<const Parser*>>(
                     {{parser1.mime_types.at(0), {&parser1}}, {parser2.mime_types.at(0).mainType(), {&parser2}}}));
    }

    SUBCASE("multiple parsers, just one 'public'") {
        const Parser parser1("Parser1", true, Parse1Function(), Parse2Function<int>(), Parse3Function(), nullptr,
                             nullptr, "Parser1: description", {MIMEType("foo/bar")},
                             {ParserPort{hilti::rt::tuple::make(hilti::rt::Port(4040, hilti::rt::Protocol::TCP),
                                                                Direction::Originator)}});
        const Parser parser2("Parser2", false, Parse1Function(), Parse2Function<int>(), Parse3Function(), nullptr,
                             nullptr, "Parser2: description", {MIMEType("foo/*")},
                             {ParserPort{hilti::rt::tuple::make(hilti::rt::Port(4040, hilti::rt::Protocol::TCP),
                                                                Direction::Responder)}});
        detail::globalState()->parsers.emplace_back(&parser1);
        detail::globalState()->parsers.emplace_back(&parser2);

        init();

        const auto* gs = detail::__global_state;
        REQUIRE_NE(gs, nullptr);

        // `parser1` is the only `public` parser so it is the default.
        CHECK_EQ(*gs->default_parser, &parser1);

        CAPTURE(gs->parsers.size());
        CAPTURE(gs->parsers_by_name.size());
        CHECK_EQ(gs->parsers_by_name, std::map<std::string, std::vector<const Parser*>>(
                                          {{{parser1.name.data(), parser1.name.size()}, {&parser1}},
                                           {"4040/tcp%orig", {&parser1}},
                                           {parser1.mime_types.at(0), {&parser1}},
                                           {{parser2.name.data(), parser2.name.size()}, {&parser2}},
                                           {"4040/tcp%resp", {&parser2}}}));
        CHECK_EQ(gs->parsers_by_mime_type,
                 std::map<std::string, std::vector<const Parser*>>(
                     {{parser1.mime_types.at(0), {&parser1}}, {parser2.mime_types.at(0).mainType(), {&parser2}}}));
    }
}

TEST_CASE("isInitialized") {
    done(); // Noop if not initialized.
    REQUIRE_FALSE(isInitialized());

    init();

    CHECK(isInitialized());
}

TEST_CASE("done") {
    hilti::rt::init();
    init();
    REQUIRE_NE(detail::__global_state, nullptr);

    done();
    CHECK_EQ(detail::__global_state, nullptr);

    done();
    CHECK_EQ(detail::__global_state, nullptr);
}

TEST_SUITE_END();
