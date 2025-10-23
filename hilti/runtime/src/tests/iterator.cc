// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <type_traits>

#include <hilti/rt/iterator.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("iterator");

TEST_CASE("range") {
    auto unroll =
        [](auto&& xs) -> std::vector<std::remove_const_t<std::remove_reference_t<decltype(*std::begin(xs))>>> {
        std::vector<std::remove_const_t<std::remove_reference_t<decltype(*std::begin(xs))>>> result;
        for ( auto&& x : xs )
            result.push_back(x);
        return result;
    };

    CHECK_EQ(unroll(range(std::vector{1, 2, 3})), std::vector{1, 2, 3});

    int arr[] = {1, 2, 3};
    CHECK_EQ(unroll(range(arr)), std::vector{1, 2, 3});
}

TEST_SUITE_END();
