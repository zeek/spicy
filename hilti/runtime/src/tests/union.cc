// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <string>

#include <hilti/rt/doctest.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/union.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("union");

TEST_CASE("get") {
    CHECK_EQ(union_::get<0>(Union<int>()), std::monostate());
    CHECK_THROWS_WITH_AS(union_::get<1>(Union<int>()), "access to union member that does not hold value",
                         const UnsetUnionMember&);

    CHECK_THROWS_WITH_AS(union_::get<0>(Union<int>(42)), "access to union member that does not hold value",
                         const UnsetUnionMember&);
    CHECK_EQ(union_::get<1>(Union<int>(42)), 42);

    CHECK_THROWS_WITH_AS(union_::get<0>(Union<int, std::string, double>("abc")),
                         "access to union member that does not hold value", const UnsetUnionMember&);
    CHECK_THROWS_WITH_AS(union_::get<1>(Union<int, std::string, double>("abc")),
                         "access to union member that does not hold value", const UnsetUnionMember&);
    CHECK_EQ(union_::get<2>(Union<int, std::string, double>("abc")), "abc");
    CHECK_THROWS_WITH_AS(union_::get<3>(Union<int, std::string, double>("abc")),
                         "access to union member that does not hold value", const UnsetUnionMember&);
}

TEST_CASE("get_proxy") {
    auto u = Union<int, std::string, double>("abc");
    REQUIRE_EQ(u.index(), 2);
    REQUIRE_EQ(union_::get<2>(u), "abc");

    // `get_proxy` is lazy.
    union_::get_proxy<0>(u);
    REQUIRE_EQ(u.index(), 2);

    // We can reassign to the set field.
    union_::get_proxy<2>(u) = "def";
    CHECK_EQ(union_::get<2>(u), "def");

    // We can change which field is set.
    union_::get_proxy<1>(u) = 42;
    CHECK_EQ(u.index(), 1u);
    CHECK_EQ(union_::get<1>(u), 42);
}

TEST_SUITE_END();

TEST_SUITE_BEGIN("Union");

TEST_CASE("assign") {
    SUBCASE("lvalue") {
        Union<int, std::string> u("abc");
        REQUIRE_EQ(u.index(), 2u);

        // Not changing field.
        const std::string s = "def";
        u = s;
        CHECK_EQ(u.index(), 2u);

        // Changing field.
        u = 42;
        CHECK_EQ(u.index(), 1u);
    }

    SUBCASE("rvalue") {
        Union<int, std::unique_ptr<double>> u(nullptr);
        REQUIRE_EQ(u.index(), 2u);

        // Not changing field.
        u = std::unique_ptr<double>(new double(1e42));
        CHECK_EQ(u.index(), 2u);

        // Changing field.
        u = 42;
        CHECK_EQ(u.index(), 1u);
    }
}

TEST_CASE("construct") {
    CHECK_EQ(union_::get<0>(Union<int, std::string>()), std::monostate());
    CHECK_EQ(union_::get<0>(Union<int, std::string>(std::monostate())), std::monostate());
    CHECK_EQ(union_::get<1>(Union<int, std::string>(42)), 42);
    CHECK_EQ(union_::get<2>(Union<int, std::string>("abc")), "abc");
}

TEST_CASE("index") {
    CHECK_EQ(Union<int, std::string>().index(), 0u);
    CHECK_EQ(Union<int, std::string>(42).index(), 1u);
    CHECK_EQ(Union<int, std::string>("abc").index(), 2u);
}

struct TestUnion : Union<int, std::string> {
    TestUnion() = default;

    template<typename T>
    TestUnion(T&& x) : Union(std::forward<T>(x)) {}

    template<typename F>
    void __visit(F f) const {
        switch ( index() ) {
            case 1: return f("int", &union_::get<1>(*this));
            case 2: return f("string", &union_::get<2>(*this));
        }
    }
};

TEST_CASE("to_string") {
    CHECK_EQ(to_string(TestUnion()), "<unset>");
    CHECK_EQ(to_string(TestUnion(42)), "$int=42");
    CHECK_EQ(to_string(TestUnion("abc")), "$string=\"abc\"");
}

TEST_SUITE_END();
