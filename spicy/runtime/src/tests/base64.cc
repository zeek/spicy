// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

#include <spicy/rt/base64.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;
using namespace spicy::rt;

TEST_SUITE_BEGIN("Base64");

TEST_CASE("decode") {
    base64::Stream stream;

    SUBCASE("Bytes") {
        SUBCASE("empty") { CHECK_EQ(base64::decode(stream, ""), ""_b); }

        SUBCASE("block w/o padding") { CHECK_EQ(base64::decode(stream, "Zm9v"_b), "foo"_b); }

        SUBCASE("block w/ padding") {
            CHECK_EQ(base64::decode(stream, "TW9yZSB0aGFuIDYgYnl0ZXM="_b), "More than 6 bytes"_b);
        }

        SUBCASE("multiple calls") {
            SUBCASE("block w/o padding") {
                CHECK_EQ(base64::decode(stream, "Zm9v"_b), "foo"_b);
                CHECK_EQ(base64::decode(stream, "Zm9v"_b), "foo"_b);
            }

            SUBCASE("block w/ padding") {
                CHECK_EQ(base64::decode(stream, "TW9yZSB0aGFu"_b), "More than"_b);
                CHECK_EQ(base64::decode(stream, "IDYgYnl0ZXM="_b), " 6 bytes"_b);
            }
        }
    }

    SUBCASE("View") {
        SUBCASE("empty") {
            Stream data("");
            CHECK_EQ(base64::decode(stream, data.view()), ""_b);
        }

        SUBCASE("block w/o padding") {
            Stream data("Zm9v");
            CHECK_EQ(base64::decode(stream, data.view()), "foo"_b);
        }

        SUBCASE("block w/ padding") {
            Stream data("TW9yZSB0aGFuIDYgYnl0ZXM=");
            CHECK_EQ(base64::decode(stream, data.view()), "More than 6 bytes"_b);
        }

        SUBCASE("missing padding") {
            Stream data("TW9yZSB0aGFuIDYgYnl0ZXM");
            CHECK_EQ(base64::decode(stream, data.view()), "More than 6 bytes"_b);
        }

        SUBCASE("multiple calls") {
            SUBCASE("block w/o padding") {
                Stream data("Zm9v");
                CHECK_EQ(base64::decode(stream, data.view()), "foo"_b);
                data.append("Zm9v");
                CHECK_EQ(base64::decode(stream, data.view()), "foofoo"_b);
            }

            SUBCASE("block w/ padding") {
                Stream data("TW9yZSB0aGFu");
                CHECK_EQ(base64::decode(stream, data.view()), "More than"_b);
                data.append("IDYgYnl0ZXM");
                CHECK_EQ(base64::decode(stream, data.view()), "More than 6 bytes"_b);
            }
        }
    }
}

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

TEST_CASE("finish") {
    base64::Stream stream;
    CHECK_EQ(base64::finish(stream), ""_b);

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    CHECK_THROWS_WITH_AS(base64::finish(stream), "stream already finished", const base64::Base64Error&);
}

TEST_SUITE_END();
