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

TEST_SUITE_END();
