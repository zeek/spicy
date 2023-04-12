// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>

#include <spicy/rt/zlib_.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;
using namespace spicy::rt;

TEST_SUITE_BEGIN("Zlib");

TEST_CASE("decompress") {
    zlib::Stream stream;

    SUBCASE("Bytes") {
        SUBCASE("nothing") {
            CHECK_EQ(zlib::decompress(stream, ""_b), ""_b);
            CHECK_EQ(zlib::finish(stream), ""_b);
        }

        SUBCASE("single block") {
            CHECK_EQ(zlib::decompress(stream, "x\x01\x01\x03\x00\xfc\xff\x00\x01\x02\x00\x07\x00\x04"_b),
                     "\x00\x01\x02"_b);
            CHECK_EQ(zlib::finish(stream), ""_b);
        }

        SUBCASE("raw deflate") {
            auto raw_stream = zlib::Stream(-15);
            CHECK_EQ(zlib::decompress(raw_stream, "\x33\x34\x84\x01\x2e\x00"_b), "1111111111\n"_b);
            CHECK_EQ(zlib::finish(raw_stream), ""_b);
        }

        SUBCASE("multiple blocks") {
            auto decompress = zlib::decompress(stream, "x\x01\x01\x03\x00\xfc\xff\x00\x01\x02\x00\x07\x00\x04"_b);
            decompress.append(zlib::decompress(stream, "\x00\x01\x02"_b));
            decompress.append(zlib::finish(stream));

            CHECK_EQ(decompress, "\x00\x01\x02"_b);
        }

        SUBCASE("error") {
            // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
            CHECK_THROWS_WITH_AS(zlib::decompress(stream, "\x01\x02\x03"_b), "inflate failed", const zlib::ZlibError&);
        }

        SUBCASE("reused stream") {
            // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
            CHECK_THROWS_WITH_AS(zlib::decompress(stream, "invalid data"_b), "inflate failed", const zlib::ZlibError&);

            // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
            CHECK_THROWS_WITH_AS(zlib::decompress(stream, "x\x01\x01\x03\x00\xfc\xff\x00\x01\x02\x00\x07\x00\x04"_b),
                                 "error'ed zlib stream cannot be reused", const zlib::ZlibError&);
            CHECK_EQ(zlib::finish(stream), ""_b);
        }
    }

    SUBCASE("View") {
        Stream data;

        SUBCASE("nothing") {
            CHECK_EQ(zlib::decompress(stream, data.view()), ""_b);
            CHECK_EQ(zlib::finish(stream), ""_b);
        }

        SUBCASE("single block") {
            data.append("x\x01\x01\x03\x00\xfc\xff\x00\x01\x02\x00\x07\x00\x04"_b);
            CHECK_EQ(zlib::decompress(stream, data.view()), "\x00\x01\x02"_b);
            CHECK_EQ(zlib::finish(stream), ""_b);
        }

        SUBCASE("multiple blocks") {
            data.append("x\x01\x01\x03\x00\xfc\xff"_b);
            data.append("\x00\x01\x02\x00\x07\x00\x04"_b);
            CHECK_EQ(zlib::decompress(stream, data.view()), "\x00\x01\x02"_b);
            CHECK_EQ(zlib::finish(stream), ""_b);
        }

        SUBCASE("error") {
            data.append("\x01\x02\x03"_b);
            // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
            CHECK_THROWS_WITH_AS(zlib::decompress(stream, data.view()), "inflate failed", const zlib::ZlibError&);
        }

        SUBCASE("reused stream") {
            // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
            CHECK_THROWS_WITH_AS(zlib::decompress(stream, "invalid data"), "inflate failed", const zlib::ZlibError&);

            data.append("x\x01\x01\x03\x00\xfc\xff\x00\x01\x02\x00\x07\x00\x04"_b);

            // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
            CHECK_THROWS_WITH_AS(zlib::decompress(stream, data.view()), "error'ed zlib stream cannot be reused",
                                 const zlib::ZlibError&);
        }
    }
}

TEST_CASE("to_string") { CHECK_EQ(to_string(zlib::Stream()), "<zlib stream>"); }

TEST_CASE("crc32") {
    auto crc = zlib::crc32_init();
    crc = zlib::crc32_add(crc, "ABC");
    crc = zlib::crc32_add(crc, "DEF");
    crc = zlib::crc32_add(crc, "GHI");
    CHECK_EQ(crc, 0xc96b9640);
}

TEST_SUITE_END();
