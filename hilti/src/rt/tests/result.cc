#include <doctest/doctest.h>

#include <string>

#include <hilti/rt/result.h>

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

TEST_CASE("equal") {
    CHECK_EQ(Result(42), Result(42));
    CHECK_EQ(Result(0), Result(0));
    CHECK_EQ(Result<int>(result::Error("foo")), Result<int>(result::Error("foo")));
}

TEST_CASE("not equal") {
    CHECK_NE(Result(42), Result(0));
    CHECK_NE(Result(42), Result<int>(result::Error("foo")));
}

TEST_SUITE_END();
