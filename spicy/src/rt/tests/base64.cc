// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

#include <spicy/rt/base64.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;
using namespace spicy::rt;

TEST_SUITE_BEGIN("Base64");

TEST_CASE("encode") {
    base64::Stream stream;

    SUBCASE("Bytes") {
        SUBCASE("empty") {
            CHECK_EQ(base64::encode(stream, ""_b), ""_b);
            CHECK_EQ(base64::finish(stream), ""_b);
        }

        SUBCASE("sequence w/o padding") {
            CHECK_EQ(base64::encode(stream, "foo"_b), "Zm9v"_b);
            CHECK_EQ(base64::finish(stream), ""_b);
        }

        SUBCASE("sequence w/ padding") {
            CHECK_EQ(base64::encode(stream, "More than 6 bytes"_b), "TW9yZSB0aGFuIDYgYnl0ZX"_b);
            CHECK_EQ(base64::finish(stream), "M="_b);
        }

        SUBCASE("multiple calls") {
            Bytes xs;

            xs.append(base64::encode(stream, "More than"));
            CHECK_EQ(xs, "TW9yZSB0aGFu"_b);

            xs.append(base64::encode(stream, " 6 bytes"));
            CHECK_EQ(xs, "TW9yZSB0aGFuIDYgYnl0ZX"_b);

            xs.append(base64::finish(stream));
            CHECK_EQ(xs, "TW9yZSB0aGFuIDYgYnl0ZXM="_b);
        }
    }

    SUBCASE("View") {
        SUBCASE("empty") {
            Stream data("");
            CHECK_EQ(base64::encode(stream, data.view()), ""_b);
            CHECK_EQ(base64::finish(stream), ""_b);
        }

        SUBCASE("short sequence w/o padding") {
            Stream data("foo");
            CHECK_EQ(base64::encode(stream, data.view()), "Zm9v"_b);
            CHECK_EQ(base64::finish(stream), ""_b);
        }

        SUBCASE("long sequence w/ padding") {
            Stream data("More than 6 bytes");
            CHECK_EQ(base64::encode(stream, data.view()), "TW9yZSB0aGFuIDYgYnl0ZX"_b);
            CHECK_EQ(base64::finish(stream), "M="_b);
        }

        SUBCASE("multiple calls") {
            Stream data("More than");
            CHECK_EQ(base64::encode(stream, data.view()), "TW9yZSB0aGFu"_b);

            data.append(" 6 bytes");
            CHECK_EQ(base64::encode(stream, data.view()), "TW9yZSB0aGFuIDYgYnl0ZX"_b);

            CHECK_EQ(base64::finish(stream), "M="_b);
        }
    }
}

TEST_SUITE_END();
