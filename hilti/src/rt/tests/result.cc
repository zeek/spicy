#include <doctest/doctest.h>

#include <string>

#include <hilti/rt/result.h>

using namespace hilti::rt;

TEST_CASE_TEMPLATE("Result", T, Nothing, bool, std::string) {
    SUBCASE("default constructed is error") {
        Result<T> r;
        CHECK(! r);
        CHECK(r.errorOrThrow() == result::Error("<result not initialized>"));
    }

    SUBCASE("conversion to bool") {
        Result<T> r;
        CHECK(! r);

        if constexpr ( std::is_same_v<T, void> )
            r = Nothing();
        else
            r = T{};

        CHECK(r);
    }
}
