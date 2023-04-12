// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/exception.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/reference.h>

#include <spicy/rt/parsed-unit.h>

using namespace hilti::rt;
using namespace spicy::rt;

TEST_SUITE_BEGIN("ParsedUnit");

TEST_CASE("get") {
    ParsedUnit p;

    SUBCASE("uninitialized") { CHECK_THROWS_WITH_AS(p.get<int>(), "parsed unit not set", const NullReference&); }

    SUBCASE("initialized") {
        const auto ref = ValueReference<int>(42);
        const auto type_info = TypeInfo();
        ParsedUnit::initialize(p, ref, &type_info);

        CHECK_EQ(p.get<int>(), 42);
    }
}

TEST_CASE("initialize") {
    ParsedUnit p;
    const auto ref = ValueReference<int>(42);
    const auto type_info = TypeInfo();
    ParsedUnit::initialize(p, ref, &type_info);

    CHECK_EQ(p.get<int>(), 42);
}

TEST_CASE("reset") {
    ParsedUnit p;

    SUBCASE("uninitialized") {}

    SUBCASE("initialized") {
        const auto ref = ValueReference<int>(42);
        const auto type_info = TypeInfo();
        ParsedUnit::initialize(p, ref, &type_info);

        CHECK_NOTHROW(p.get<int>());
    }

    p.reset();
    CHECK_THROWS_WITH_AS(p.get<int>(), "parsed unit not set", const NullReference&);
}

TEST_CASE("value") {
    ParsedUnit p;

    SUBCASE("uninitialized") { CHECK_THROWS_WITH_AS(p.value(), "parsed unit not set", const NullReference&); }

    SUBCASE("initialized") {
        const auto ref = ValueReference<int>(42);
        const auto type_info = TypeInfo();
        ParsedUnit::initialize(p, ref, &type_info);

        CHECK_EQ(p.value(), type_info::Value(ref.get(), &type_info, p));
    }
}

TEST_CASE("to_string") {
    ParsedUnit p;

    CHECK_EQ(to_string(p), "<parsed unit>");

    std::stringstream x;
    x << p;
    CHECK_EQ(x.str(), "<parsed unit>");
}

TEST_SUITE_END();
