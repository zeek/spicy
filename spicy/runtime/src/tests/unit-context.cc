// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/bytes.h>

#include <spicy/rt/unit-context.h>

using namespace hilti::rt::bytes;
using namespace spicy::rt;

TEST_SUITE_BEGIN("unit context");

TEST_CASE("copy context") {
    auto b = hilti::rt::reference::make_strong<hilti::rt::Bytes>("x"_b);
    auto c1 = UnitContext(std::move(b), &hilti::rt::type_info::bytes);

    // Copy context by reference
    const UnitContext& c2 = c1;

    // Modify value
    auto b1 = c1.as<hilti::rt::Bytes>(&hilti::rt::type_info::bytes);
    b1->append("y"_b);

    // Check that modification is visible through 2nd context instance
    CHECK_EQ(*c2.as<hilti::rt::Bytes>(&hilti::rt::type_info::bytes), "xy"_b);

    // Catch type mismatch
    CHECK_THROWS_AS(c2.as<std::string>(&hilti::rt::type_info::string), ContextMismatch);
}

TEST_CASE("create and set") {
    auto b = hilti::rt::reference::make_strong<hilti::rt::Bytes>("x"_b);
    auto c = spicy::rt::detail::createContext(b, &hilti::rt::type_info::bytes);

    hilti::rt::StrongReference<hilti::rt::Bytes> __context;

    // Set __context
    spicy::rt::detail::setContext(__context, nullptr, c, &hilti::rt::type_info::bytes);
    CHECK_EQ(*__context, "x"_b);

    // Unset __context
    spicy::rt::detail::setContext(__context, nullptr, {}, &hilti::rt::type_info::bytes);
    CHECK(! __context);

    // Catch type mismatch
    CHECK_THROWS_AS(spicy::rt::detail::setContext(__context, nullptr, c, &hilti::rt::type_info::string),
                    ContextMismatch);
}

TEST_CASE("to_string") {
    auto b = hilti::rt::reference::make_strong<hilti::rt::Bytes>("x"_b);
    CHECK_EQ(hilti::rt::to_string(UnitContext(std::move(b), &hilti::rt::type_info::bytes)), "<unit context>");
}

TEST_SUITE_END();
