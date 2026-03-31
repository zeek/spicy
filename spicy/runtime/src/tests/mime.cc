// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/extension-points.h>

#include <spicy/rt/mime.h>

using namespace hilti::rt;
using namespace hilti::rt::string::literals;
using namespace spicy::rt;

TEST_SUITE_BEGIN("MimeType");

TEST_CASE("construct") {
    SUBCASE("default") {
        MIMEType m;
        CHECK_THROWS_WITH_AS(m.mainType(), "MIME type is uninitialized", const InvalidMIMEType&);
        CHECK_THROWS_WITH_AS(m.subType(), "MIME type is uninitialized", const InvalidMIMEType&);
    }

    SUBCASE("from main/sub") {
        MIMEType m("main", "sub");
        CHECK_EQ(m.mainType(), "main");
        CHECK_EQ(m.subType(), "sub");
    }

    SUBCASE("from type") {
        SUBCASE("full type") {
            MIMEType m("main/sub"_hs);
            CHECK_EQ(m.mainType(), "main");
            CHECK_EQ(m.subType(), "sub");
        }

        SUBCASE("wildcard main type") {
            MIMEType m("*/sub"_hs);
            CHECK_EQ(m.mainType(), "*");
            CHECK_EQ(m.subType(), "sub");
        }

        SUBCASE("wildcard sub type") {
            MIMEType m("main/*"_hs);
            CHECK_EQ(m.mainType(), "main");
            CHECK_EQ(m.subType(), "*");
        }

        SUBCASE("full wildcard") {
            MIMEType m("*/*"_hs);
            CHECK_EQ(m.mainType(), "*");
            CHECK_EQ(m.subType(), "*");
        }

        SUBCASE("not parseable") {
            CHECK_THROWS_WITH_AS(MIMEType(""_hs), "cannot parse MIME type ''", const InvalidMIMEType&);
            CHECK_THROWS_WITH_AS(MIMEType("foo"_hs), "cannot parse MIME type 'foo'", const InvalidMIMEType&);
            CHECK_THROWS_WITH_AS(MIMEType("main/"_hs), "cannot parse MIME type 'main/'", const InvalidMIMEType&);
            CHECK_THROWS_WITH_AS(MIMEType("/sub"_hs), "cannot parse MIME type '/sub'", const InvalidMIMEType&);
        }
    }
}

TEST_CASE("asKey") {
    CHECK_EQ(MIMEType("main/sub"_hs).asKey(), "main/sub");
    CHECK_EQ(MIMEType("main/*"_hs).asKey(), "main");
    CHECK_EQ(MIMEType("*/sub"_hs).asKey(), "");
    CHECK_EQ(MIMEType("*/*"_hs).asKey(), "");
}

TEST_CASE("isWildcard") {
    CHECK_FALSE(MIMEType("main/sub"_hs).isWildcard());
    CHECK(MIMEType("main/*"_hs).isWildcard());
    CHECK(MIMEType("*/sub"_hs).isWildcard());
    CHECK(MIMEType("*/*"_hs).isWildcard());
}

TEST_CASE("parse") {
    CHECK_EQ(MIMEType::parse("main/sub"_hs), MIMEType("main"_hs, "sub"_hs));
    CHECK_EQ(MIMEType::parse("foo"_hs), result::Error("cannot parse MIME type 'foo'"));
}

TEST_CASE("to_string") {
    CHECK_THROWS_WITH_AS(to_string(MIMEType()), "MIME type is uninitialized", const InvalidMIMEType&);
    CHECK_EQ(to_string(MIMEType("main"_hs, "sub"_hs)), "main/sub");
}

TEST_SUITE_END();
