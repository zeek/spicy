// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <optional>

#include <hilti/rt/types/struct.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("struct");

TEST_CASE("value_or_exception") {
    CHECK_EQ(struct_::value_or_exception(std::optional<int>(42), "location:123"), 42);

    CHECK_THROWS_WITH_AS(struct_::value_or_exception(std::optional<int>(std::nullopt), "location:123"),
                         "struct attribute not set (location:123)", const AttributeNotSet&);
}

TEST_SUITE_END();
