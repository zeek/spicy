// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <memory>
#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/types/union.h>

using namespace hilti::rt;
using namespace hilti::rt::string::literals;

TEST_SUITE_BEGIN("union");

TEST_CASE("get") {
    CHECK_EQ(union_::get<0>(Union<int>()), std::monostate());
    CHECK_THROWS_WITH_AS(union_::get<1>(Union<int>()), "access to union member that does not hold value",
                         const UnsetUnionMember&);

    CHECK_THROWS_WITH_AS(union_::get<0>(Union<int>(42)), "access to union member that does not hold value",
                         const UnsetUnionMember&);
    CHECK_EQ(union_::get<1>(Union<int>(42)), 42);

    CHECK_THROWS_WITH_AS(union_::get<0>(Union<int, String, double>("abc"_hs)),
                         "access to union member that does not hold value", const UnsetUnionMember&);
    CHECK_THROWS_WITH_AS(union_::get<1>(Union<int, String, double>("abc"_hs)),
                         "access to union member that does not hold value", const UnsetUnionMember&);
    CHECK_EQ(union_::get<2>(Union<int, String, double>("abc"_hs)), "abc");
    CHECK_THROWS_WITH_AS(union_::get<3>(Union<int, String, double>("abc"_hs)),
                         "access to union member that does not hold value", const UnsetUnionMember&);
}

TEST_CASE("get_proxy") {
    auto u = Union<int, String, double>("abc"_hs);
    REQUIRE_EQ(u.index(), 2);
    REQUIRE_EQ(union_::get<2>(u), "abc"_hs);

    // `get_proxy` is lazy.
    union_::get_proxy<0>(u);
    REQUIRE_EQ(u.index(), 2);

    // We can reassign to the set field.
    union_::get_proxy<2>(u) = "def"_hs;
    CHECK_EQ(union_::get<2>(u), "def"_hs);

    // We can change which field is set.
    union_::get_proxy<1>(u) = 42;
    CHECK_EQ(u.index(), 1U);
    CHECK_EQ(union_::get<1>(u), 42);
}

TEST_SUITE_END();

TEST_SUITE_BEGIN("Union");

TEST_CASE("assign") {
    SUBCASE("lvalue") {
        Union<int, String> u("abc"_hs);
        REQUIRE_EQ(u.index(), 2U);

        // Not changing field.
        String s("def");
        u = s;
        CHECK_EQ(u.index(), 2U);

        // Changing field.
        u = 42;
        CHECK_EQ(u.index(), 1U);
    }

    SUBCASE("rvalue") {
        Union<int, std::unique_ptr<double>> u(nullptr);
        REQUIRE_EQ(u.index(), 2U);

        // Not changing field.
        u = std::make_unique<double>(1e42);
        CHECK_EQ(u.index(), 2U);

        // Changing field.
        u = 42;
        CHECK_EQ(u.index(), 1U);
    }
}

TEST_CASE("construct") {
    CHECK_EQ(union_::get<0>(Union<int, String>()), std::monostate());
    CHECK_EQ(union_::get<0>(Union<int, String>(std::monostate())), std::monostate());
    CHECK_EQ(union_::get<1>(Union<int, String>(42)), 42);
    CHECK_EQ(union_::get<2>(Union<int, String>("abc"_hs)), "abc"_hs);
}

TEST_CASE("index") {
    CHECK_EQ(Union<int, String>().index(), 0U);
    CHECK_EQ(Union<int, String>(42).index(), 1U);
    CHECK_EQ(Union<int, String>("abc"_hs).index(), 2U);
}

struct TestUnion : Union<int, String> {
    TestUnion() = default;

    template<typename T>
    // NOLINTNEXTLINE(bugprone-forwarding-reference-overload)
    TestUnion(T&& x) : Union(std::forward<T>(x)) {}

    std::string __to_string() const {
        if ( const auto* x = std::get_if<1>(&this->value) )
            return "$int=" + to_string(*x);
        else if ( const auto* x = std::get_if<2>(&this->value) )
            return "$string=" + to_string(*x);
        else
            return "<unset>";
    }
};

TEST_CASE("to_string") {
    CHECK_EQ(to_string(TestUnion()), "<unset>");
    CHECK_EQ(to_string(TestUnion(42)), "$int=42");
    CHECK_EQ(to_string(TestUnion("abc"_hs)), "$string=\"abc\"");
}

TEST_SUITE_END();
