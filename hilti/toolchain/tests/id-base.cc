// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
#include <doctest/doctest.h>

#include <string>

#include <hilti/autogen/config.h>
#include <hilti/base/id-base.h>

using namespace hilti;

static std::optional<std::string> normalizeID(std::string_view id) {
    if ( id.substr(0, 1) == "%" )
        return std::string("XXX_") + std::string(id.substr(1));

    return std::nullopt;
}

class ID : public detail::IDBase<ID, normalizeID> {
    using Base = detail::IDBase<ID, normalizeID>;
    using Base::IDBase;
};

TEST_SUITE_BEGIN("IDBase");

TEST_CASE("ctor") {
    CHECK_EQ(ID("").length(), 0);
    CHECK(ID("").empty());
    CHECK_EQ(ID().length(), 0);
    CHECK(ID().empty());
    CHECK_EQ(ID("a::b::c").length(), 3);
    CHECK(! ID("a::b::c").empty());
    CHECK_EQ(ID("a").length(), 1);
    CHECK_EQ(ID{"a", "b", "c"}.length(), 3);
    CHECK_EQ(ID{"a"}.length(), 1);
    CHECK_EQ(ID{"::a"}.length(), 2); // we count the empty string before the first ::
}

TEST_CASE("concat") {
    CHECK_EQ(ID("a"), ID("a"));
    CHECK_EQ(ID("a") + ID("b"), ID("a::b"));
    CHECK_EQ(ID("a") + ID("b") + ID("c"), ID("a::b::c"));
    CHECK_EQ(ID() + ID("b"), ID("b"));
    CHECK_EQ(ID("a") + ID(), ID("a"));
}

TEST_CASE("components") {
    auto id = ID("a::b::c");
    CHECK_EQ(id.str(), "a::b::c");
    CHECK_EQ(id.local(), ID("c"));
    CHECK_EQ(std::string(id.sub(0)), "a");
    CHECK_EQ(id.sub(1), ID("b"));
    CHECK_EQ(id.sub(2), ID("c"));
    CHECK_EQ(id.sub(-1), ID("c"));
    CHECK_EQ(id.sub(-2), ID("b"));
    CHECK_EQ(id.sub(-3), ID("a"));

    CHECK_EQ(id.sub(1, 3), ID("b::c"));
    CHECK_EQ(id.sub(0, -2), ID("a::b"));
    CHECK_EQ(id.sub(1, 1), ID(""));

    CHECK_EQ(ID("::xxx").local(), ID("xxx"));
    CHECK_EQ(ID("::xxx").namespace_(), ID());

    auto empty = ID();
    CHECK_EQ(empty.str(), "");
    CHECK_EQ(empty.local(), ID(""));
    CHECK_EQ(empty.namespace_(), ID(""));
    CHECK_EQ(empty.sub(0), ID(""));
    CHECK_EQ(empty.sub(-1), ID(""));
}

TEST_CASE("absolute") {
    CHECK_EQ(ID("a::b::c").isAbsolute(), false);
    CHECK_EQ(ID("::a::b::c").isAbsolute(), true);
    CHECK_EQ(ID("::a::b::c").sub(0), ID());
    CHECK_EQ(ID("a::b::c").makeAbsolute().isAbsolute(), true);
    CHECK_EQ(ID("a::b::c").makeAbsolute().str(), "::a::b::c");
    CHECK_EQ(ID().isAbsolute(), false);
    CHECK_EQ(ID().makeAbsolute().isAbsolute(), true); // not very useful but consistent
}

TEST_CASE("relative-to") {
    CHECK_EQ(ID("a::b::c").relativeTo(ID("a::b")), ID("c"));
    CHECK_EQ(ID("a::b::c").relativeTo(ID("a::b::c")), ID());
    CHECK_EQ(ID("c").relativeTo(ID("a::b")), ID("a::b::c"));
}

TEST_CASE("normalize") { CHECK_EQ(ID("%a::%b::%c").str(), "XXX_a::XXX_b::XXX_c"); }

TEST_SUITE_END();
