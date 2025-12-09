// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <memory>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>
#include <hilti/rt/test/utils.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/types/vector.h>

#include <spicy/rt/driver.h>
#include <spicy/rt/filter.h>
#include <spicy/rt/init.h>
#include <spicy/rt/parser.h>
#include <spicy/rt/typedefs.h>

using hilti::rt::Bytes;
using hilti::rt::fmt;
using hilti::rt::Nothing;
using hilti::rt::Port;
using hilti::rt::Protocol;
using hilti::rt::to_string;
using hilti::rt::Vector;
using namespace hilti::rt::bytes::literals;
using namespace spicy::rt;

TEST_SUITE_BEGIN("Parser");

TEST_CASE("Direction") {
    CHECK_EQ(to_string(Enum(Direction::Originator)), "originator");
    CHECK_EQ(to_string(Enum(Direction::Responder)), "responder");
    CHECK_EQ(to_string(Enum(Direction::Both)), "both");
    CHECK_EQ(to_string(Enum(Direction::Undef)), "undefined");

    CHECK_EQ(fmt("%s", Enum(Direction::Originator)), "originator");
    CHECK_EQ(fmt("%s", Enum(Direction::Responder)), "responder");
    CHECK_EQ(fmt("%s", Enum(Direction::Both)), "both");
    CHECK_EQ(fmt("%s", Enum(Direction::Undef)), "undefined");
}

TEST_CASE("ParserPort") {
    CHECK_EQ(to_string(ParserPort(hilti::rt::tuple::make(Port(80, Protocol::TCP), Direction::Originator))),
             "80/tcp (originator direction)");
    CHECK_EQ(to_string(ParserPort(hilti::rt::tuple::make(Port(80, Protocol::TCP), Direction::Both))), "80/tcp");

    CHECK_EQ(fmt("%s", ParserPort(hilti::rt::tuple::make(Port(80, Protocol::TCP), Direction::Originator))),
             "80/tcp (originator direction)");
    CHECK_EQ(fmt("%s", ParserPort(hilti::rt::tuple::make(Port(80, Protocol::TCP), Direction::Both))), "80/tcp");
}

TEST_CASE("atEod") {
    auto stream = hilti::rt::ValueReference<hilti::rt::Stream>();
    auto filters = hilti::rt::StrongReference<filter::detail::Filters>();

    SUBCASE("empty") {
        bool expanding = false;
        SUBCASE("expanding view") { expanding = true; }
        SUBCASE("not expanding view") { expanding = false; }

        stream->freeze();
        CHECK(detail::atEod(stream, stream->view(expanding), filters));
    }

    SUBCASE("not empty") {
        SUBCASE("expanding view") {
            // View can be advanced beyond the end of the stream without us hitting EOD.
            stream->append("\x01\x02\x03");
            auto view = stream->view();

            for ( size_t i = 0; i < stream->size() + 5; ++i ) {
                view.advance(i);
                CAPTURE(i);
                CHECK_FALSE(detail::atEod(stream, view, filters));
            }

            stream->freeze();
            CHECK_FALSE(detail::atEod(stream, view, filters));
            CHECK_FALSE(detail::atEod(stream, stream->view(), filters));
        }

        SUBCASE("trimmed view") {
            // View can be advanced beyond the end of the stream without us hitting EOD.
            stream->append("\x01\x02\x03");
            auto view = stream->view(false);
            stream->freeze();

            for ( size_t i = 0; i < stream->size() + 5; ++i ) {
                CAPTURE(i);
                view = view.trim(view.begin() + i);
                if ( i < 2 ) {
                    CHECK_FALSE(detail::atEod(stream, view, filters));
                }
                else {
                    CHECK(detail::atEod(stream, view, filters));
                }
            }
        }
    }
}

struct UnitWithSinkSupport : std::enable_shared_from_this<UnitWithSinkSupport> {
    static Parser HILTI_INTERNAL(parser);
    sink::detail::State* HILTI_INTERNAL(sink) = nullptr;
    hilti::rt::Optional<hilti::rt::RecoverableFailure> HILTI_INTERNAL(error);

    void (*HILTI_INTERNAL(on_0x25_gap))(uint64_t, uint64_t) = nullptr;
    void (*HILTI_INTERNAL(on_0x25_skipped))(uint64_t) = nullptr;
    void (*HILTI_INTERNAL(on_0x25_overlap))(uint64_t, const Bytes&, const Bytes&) = nullptr;
    void (*HILTI_INTERNAL(on_0x25_undelivered))(uint64_t, const Bytes&) = nullptr;

    void (*HILTI_INTERNAL(hook_gap))(hilti::rt::StrongReferenceGeneric, uint64_t, uint64_t);
    void (*HILTI_INTERNAL(hook_overlap))(hilti::rt::StrongReferenceGeneric, uint64_t, const hilti::rt::Bytes&,
                                         const hilti::rt::Bytes&) = nullptr;
    void (*HILTI_INTERNAL(hook_skipped))(hilti::rt::StrongReferenceGeneric, uint64_t) = nullptr;
    void (*HILTI_INTERNAL(hook_undelivered))(hilti::rt::StrongReferenceGeneric, uint64_t,
                                             const hilti::rt::Bytes&) = nullptr;

    // NOLINTNEXTLINE(bugprone-unhandled-self-assignment, cert-oop54-cpp)
    UnitWithSinkSupport& operator=(const UnitWithSinkSupport&) {
        // Not implemented.
        return *this;
    }
};

Parser UnitWithSinkSupport::HILTI_INTERNAL(parser){};

TEST_CASE("registerParser") {
    hilti::rt::test::CaptureIO _(std::cerr); // Suppress output.

    SUBCASE("w/o sink support") {
        done(); // Ensure no parsers are registered, yet.
        REQUIRE(detail::globalState()->parsers.empty());

        Parser parser;
        parser.mime_types = {MIMEType("foo/bar"), MIMEType("foo/*")};
        REQUIRE_FALSE(parser.__parse_sink);
        REQUIRE_FALSE(parser.__hook_gap);
        REQUIRE_FALSE(parser.__hook_overlap);
        REQUIRE_FALSE(parser.__hook_skipped);
        REQUIRE_FALSE(parser.__hook_undelivered);

        detail::registerParser(parser, 123, UnitRef<int>(), nullptr);

        REQUIRE_EQ(detail::globalState()->parsers.size(), 1U);
        CHECK_EQ(detail::globalState()->parsers.at(0), &parser);

        CHECK_EQ(parser.linker_scope, 123);
        CHECK_FALSE(parser.__parse_sink);
        CHECK_FALSE(parser.__hook_gap);
        CHECK_FALSE(parser.__hook_overlap);
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
        CHECK_FALSE(parser.__hook_overlap);
        REQUIRE_FALSE(parser.__hook_skipped);
        REQUIRE_FALSE(parser.__hook_undelivered);

        detail::registerParser(parser, 123, UnitRef<UnitWithSinkSupport>(), nullptr);

        REQUIRE_EQ(detail::globalState()->parsers.size(), 1U);
        CHECK_EQ(detail::globalState()->parsers.at(0), &parser);

        CHECK_EQ(parser.linker_scope, 123);
        CHECK(parser.__parse_sink);
        CHECK(parser.__hook_gap);
        CHECK(parser.__hook_overlap);
        CHECK(parser.__hook_skipped);
        CHECK(parser.__hook_undelivered);
    }

    SUBCASE("private parser") {
        done(); // Ensure no parsers are registered, yet.
        REQUIRE(detail::globalState()->parsers.empty());

        Parser parser;
        parser.mime_types = {MIMEType("foo/bar"), MIMEType("foo/*")};

        detail::registerParser(parser, 123, UnitRef<UnitWithSinkSupport>(), nullptr);

        REQUIRE_EQ(detail::globalState()->parsers.size(), 1U);
        CHECK_EQ(detail::globalState()->parsers.at(0), &parser);
    }
}

TEST_CASE("registerParserAlias") {
    done(); // ensure no parsers are registered yet
    REQUIRE(detail::globalState()->parsers.empty());

    Parser parser;
    parser.name = "parser";
    parser.is_public = true;
    detail::registerParser(parser, 123, UnitRef<int>(), nullptr);
    detail::__global_state->runtime_is_initialized = false;
    init(); // populates the alias table

    Driver driver;
    auto parser_ = driver.lookupParser("parser");
    CHECK(parser_);

    CHECK(driver.lookupParser("parser", 123));
    CHECK(! driver.lookupParser("parser", 9999));

    CHECK(registerParserAlias("parser", "alias1"));
    CHECK_EQ(driver.lookupParser("alias1"), parser_);
    CHECK_EQ(driver.lookupParser("alias1%orig"), parser_);
    CHECK_EQ(driver.lookupParser("alias1%resp"), parser_);

    CHECK(registerParserAlias("parser", "alias2%orig"));
    CHECK_EQ(driver.lookupParser("alias2%orig"), parser_);
    CHECK_FALSE(driver.lookupParser("alias2%resp"));
    CHECK_FALSE(driver.lookupParser("alias2"));

    CHECK_FALSE(registerParserAlias("does-not-exist", "alias3"));
    CHECK_FALSE(registerParserAlias("parser", ""));
}

TEST_CASE("waitForEod") {
    hilti::rt::test::CaptureIO _(std::cerr); // Suppress output.

    hilti::rt::init(); // Noop if already initialized.

    auto data = hilti::rt::ValueReference<hilti::rt::Stream>();
    auto view = data->view();
    auto filters = hilti::rt::StrongReference<filter::detail::Filters>();

    auto _waitForEod = [&](hilti::rt::resumable::Handle*) {
        detail::waitForEod(data, view, filters);
        return Nothing();
    };
    auto waitForEod = [&]() { return hilti::rt::fiber::execute(_waitForEod); };

    SUBCASE("open ended") { view = data->view(true); }
    SUBCASE("closed view") { view = hilti::rt::stream::View{data->begin(), data->begin() + 1}; }

    auto wait1 = waitForEod();
    CHECK_FALSE(wait1);
    data->freeze();

    auto wait2 = waitForEod();
    CHECK(wait2);
}

TEST_CASE("waitForInput") {
    hilti::rt::test::CaptureIO _(std::cerr); // Suppress output.

    hilti::rt::init(); // Noop if already initialized.

    auto data = hilti::rt::ValueReference<hilti::rt::Stream>();
    auto view = data->view();

    auto filters = hilti::rt::StrongReference<filter::detail::Filters>();

    auto _waitForInput = [&](hilti::rt::resumable::Handle*) {
        detail::waitForInput(data, view, "error message", "location", filters);
        return Nothing();
    };

    auto waitForInput = [&]() { return hilti::rt::fiber::execute(_waitForInput); };

    SUBCASE("not enough data") {
        // `waitForInput` yields if not enough data available. We
        // can only wait from inside a `Resumable`.
        auto wait = waitForInput();
        CHECK_FALSE(wait);
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
        CHECK_THROWS_WITH_AS(waitForInput(), "error message (0 bytes available) (location)", const ParseError&);
    }
}

TEST_CASE("waitForInput with min") {
    hilti::rt::test::CaptureIO _(std::cerr); // Suppress output.

    hilti::rt::init(); // Noop if already initialized.

    auto data = hilti::rt::ValueReference<hilti::rt::Stream>();
    auto view = data->view();

    auto filters = hilti::rt::StrongReference<filter::detail::Filters>();

    auto _waitForInput = [&](hilti::rt::resumable::Handle*) {
        detail::waitForInput(data, view, 3, "error message", "location", filters);
        return true;
    };

    auto waitForInput = [&]() { return hilti::rt::fiber::execute(_waitForInput); };

    SUBCASE("not enough data") {
        // `waitForInput` yields if not enough data available. We
        // can only wait from `Resumable`.
        auto wait = waitForInput();
        CHECK_FALSE(wait);
        CHECK_THROWS_WITH_AS(_waitForInput(nullptr), "'yield' in non-suspendable context",
                             const hilti::rt::RuntimeError&);
    }

    SUBCASE("enough data") {
        // With enough data available we can get a result.
        data->append("\x01\x02"_b);
        REQUIRE_EQ(data->size(), 2);
        auto wait = waitForInput();
        CHECK_FALSE(wait); // Still need one more byte.

        data->append("\x03");
        REQUIRE_EQ(data->size(), 3);
        const auto res = waitForInput();
        REQUIRE(res);
        CHECK(res.get<bool>());
    }

    SUBCASE("eod") {
        data->freeze();
        CHECK_THROWS_WITH_AS(waitForInput(), "error message (0 bytes available) (location)", const ParseError&);
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
        auto wait = waitForInputOrEod();
        CHECK_FALSE(wait);
        CHECK_THROWS_WITH_AS(_waitForInputOrEod(nullptr), "'yield' in non-suspendable context",
                             const hilti::rt::RuntimeError&);
    }

    SUBCASE("enough data") {
        // With enough data available we can get a result.
        data->append("\x01\x02"_b);
        REQUIRE_EQ(data->size(), 2);
        auto wait = waitForInputOrEod();
        CHECK_FALSE(wait); // Still need one more byte.

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

            int called1 = 0;
            int called2 = 0;

            // We add two filters. We need to run them once for them to
            // yield, so that we can resume them later when
            // waitForInputOrEod() flushes all filters.

            filters->push_back(filter::detail::OneFilter({}, {}, {}, [&](hilti::rt::resumable::Handle* h) {
                if ( ++called1 == 1 )
                    h->yield();
                ++called1;
                return Nothing();
            }));

            filters->push_back(filter::detail::OneFilter({}, {}, {}, [&](hilti::rt::resumable::Handle* h) {
                if ( ++called2 == 1 )
                    h->yield();
                ++called2;
                return Nothing();
            }));

            REQUIRE_EQ(called1, 0);
            REQUIRE_EQ(called2, 0);

            (*filters)[0].resumable.run();
            (*filters)[1].resumable.run();

            CHECK_EQ(called1, 1);
            CHECK_EQ(called2, 1);

            // We trigger waiting for input with not enough data available and
            // resume later as `waitForInputOrEod` would short-circuit were
            // enough data available initially.
            auto res = waitForInputOrEod();
            data->append("\x01\x02\x03"_b);
            res.resume(); // XX

            CHECK(res);
            CHECK_EQ(called1, 2);
            CHECK_EQ(called2, 2);
        }
    }
}

TEST_CASE("extractBytes") {
    // Most of the work in extractBytes() is done through the waitFor...()
    // functions, which we test separately.

    auto data = hilti::rt::ValueReference<hilti::rt::Stream>();
    data->append("12345");
    data->freeze();
    auto view = data->view();

    SUBCASE("without eod") {
        CHECK_EQ(detail::extractBytes(data, data->view(), 5, false, "<location>", {}), hilti::rt::Bytes("12345"));
        CHECK_THROWS_WITH_AS(detail::extractBytes(data, data->view(), 10, false, "<location>", {}),
                             "expected 10 bytes (5 available) (<location>)", const spicy::rt::ParseError&);
    }

    SUBCASE("with eod") {
        CHECK_EQ(detail::extractBytes(data, data->view(), 5, true, "<location>", {}), hilti::rt::Bytes("12345"));
        CHECK_EQ(detail::extractBytes(data, data->view(), 10, true, "<location>", {}), hilti::rt::Bytes("12345"));
    }
}

TEST_CASE("expectBytesLiteral") {
    // Most of the work in extractBytesLiteral() is done through the waitFor...()
    // functions, which we test separately.

    auto data = hilti::rt::ValueReference<hilti::rt::Stream>();
    data->append("12345");
    data->freeze();
    auto view = data->view();

    CHECK_NOTHROW(detail::expectBytesLiteral(data, data->view(), "123"_b, "<location>", {}));
    CHECK_THROWS_WITH_AS(detail::expectBytesLiteral(data, data->view(), "abc"_b, "<location>", {}),
                         "expected bytes literal \"abc\" but input starts with \"123\" (<location>)",
                         const spicy::rt::ParseError&);
}

TEST_CASE("unitFind") {
    // We just tests the argument forwarding here, the matching itself is
    // covered by hilti::rt::stream::View::find().

    auto s = hilti::rt::Stream("0123456789012");
    auto begin = s.at(1);
    auto end = s.at(11);

    CHECK_EQ(*detail::unitFind(begin, end, s.at(4), "789"_b, hilti::rt::stream::Direction::Forward), s.at(7));
    CHECK_EQ(*detail::unitFind(begin, end, s.at(4), "123"_b, hilti::rt::stream::Direction::Backward), s.at(1));
    CHECK_EQ(*detail::unitFind(begin, end, {}, "1"_b, hilti::rt::stream::Direction::Forward), s.at(1));
    CHECK_EQ(*detail::unitFind(begin, end, {}, "1"_b, hilti::rt::stream::Direction::Backward), s.at(11));
    CHECK(! detail::unitFind(begin, end, s.at(4), "XYZ"_b, hilti::rt::stream::Direction::Backward));
}

TEST_SUITE_END();
