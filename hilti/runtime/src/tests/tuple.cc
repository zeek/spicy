// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/types/tuple.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Tuple");

// Returns reference to element at given index using "tuple::elementOffset()".
template<size_t Idx, typename Dst, typename Tuple>
static const Dst& get_element_ref(const Tuple& t) {
    auto ptr = reinterpret_cast<const char*>(&t) + tuple::elementOffset<Tuple, Idx>();
    return *reinterpret_cast<const Dst*>(ptr);
}

TEST_CASE("elementOffset") {
    auto t1 = std::tuple{1};
    CHECK(get_element_ref<0, int>(t1) == 1);

    auto t2 = std::tuple{true, std::string("abc"), 3.14};
    CHECK(get_element_ref<0, bool>(t2) == true);
    CHECK(get_element_ref<1, std::string>(t2) == std::string("abc"));
    CHECK(get_element_ref<2, double>(t2) == 3.14);
}

TEST_SUITE_END();
