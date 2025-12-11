// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
//
#include <doctest/doctest.h>

#include <string>
#include <string_view>
#include <type_traits>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/result.h>
#include <hilti/rt/types/string.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Result");

TEST_CASE_TEMPLATE("default constructed is error", T, Nothing, bool, std::string) {
    Result<T> r;
    CHECK(! r);
    CHECK(r.errorOrThrow() == result::Error("<result not initialized>"));
}

TEST_CASE_TEMPLATE("conversion to bool", T, Nothing, bool, std::string) {
    Result<T> r;
    CHECK(! r);

    if constexpr ( std::is_same_v<T, void> )
        r = Nothing();
    else
        r = T{};

    CHECK(r);
}

TEST_CASE("errorOrThrow") {
    CHECK_THROWS_WITH_AS(Result<int>(42).errorOrThrow(), "<no error>", const result::NoError&);
    CHECK_EQ(Result<int>().errorOrThrow(), result::Error("<result not initialized>"));
    CHECK_EQ(Result<int>(result::Error("foo")).errorOrThrow(), result::Error("foo"));
}

TEST_CASE("equal") {
    CHECK_EQ(Result(42), Result(42));
    CHECK_EQ(Result(0), Result(0));
    CHECK_EQ(Result<int>(result::Error("foo")), Result<int>(result::Error("foo")));
}

TEST_CASE("not equal") {
    CHECK_NE(Result(42), Result(0));
    CHECK_NE(Result(42), Result<int>(result::Error("foo")));
}

TEST_CASE("valueOrThrow") {
    SUBCASE("const") {
        const auto r1 = Result<int>(0);
        const auto r2 = Result<int>();
        const auto r3 = Result<int>(result::Error("foo"));

        CHECK_EQ(r1.valueOrThrow(), 0);
        CHECK_THROWS_WITH_AS(r2.valueOrThrow(), "<result not initialized>", const result::NoResult&);
        CHECK_THROWS_WITH_AS(r3.valueOrThrow(), "foo", const result::NoResult&);
    }

    SUBCASE("non const") {
        auto r1 = Result<int>(0);
        auto r2 = Result<int>();
        auto r3 = Result<int>(result::Error("foo"));

        CHECK_EQ(r1.valueOrThrow(), 0);
        CHECK_THROWS_WITH_AS(r2.valueOrThrow(), "<result not initialized>", const result::NoResult&);
        CHECK_THROWS_WITH_AS(r3.valueOrThrow(), "foo", const result::NoResult&);

        r1.valueOrThrow() += 42;
        CHECK_EQ(r1, Result(42));
    }
}

TEST_CASE("rvalue access") {
    static_assert(std::is_same_v<int, decltype(Result<int>().value())>);
    static_assert(std::is_same_v<int, decltype(Result<int>().valueOrThrow())>);
    static_assert(std::is_same_v<int, decltype(*Result<int>())>);
    static_assert(std::is_same_v<result::Error, decltype(Result<int>(result::Error("error")).error())>);
}

TEST_CASE("to_string_for_print") {
    CHECK_EQ(to_string_for_print(Result<std::string>("abc")), "abc");
    CHECK_EQ(to_string_for_print(Result<std::string>()), "<error: <result not initialized>>");

    CHECK_EQ(to_string_for_print(Result<std::string_view>("abc")), "abc");
    CHECK_EQ(to_string_for_print(Result<std::string>()), "<error: <result not initialized>>");
}

TEST_SUITE("Error") {
    TEST_CASE("string") { CHECK_EQ(result::Error("foo").operator std::string(), "foo"); }
    TEST_CASE("string_view") { CHECK_EQ(result::Error("foo").operator std::string_view(), "foo"); }

    TEST_CASE("comparison") {
        auto e1 = result::Error();
        auto e2 = result::Error("bar");

        CHECK_EQ(e1, e1);
        CHECK_EQ(e2, e2);
        CHECK_NE(e1, e2);
        CHECK_NE(e2, e1);
    }

    TEST_CASE("NoError") { CHECK_EQ(result::NoError().description(), "<no error>"); }
}

TEST_SUITE("Nothing") {
    TEST_CASE("comparison") {
        CHECK_EQ(Nothing(), Nothing());
        CHECK_FALSE(Nothing() != Nothing());
    }
}

TEST_SUITE_END();
