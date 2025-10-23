// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/bool.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/real.h>
#include <hilti/rt/types/tuple.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

// RAII helper to set the global `Configuration`'s `cout` stream.
class TestCout {
public:
    TestCout() : _prev(std::make_unique<Configuration>()) {
        _prev->cout = _cout;
        std::swap(configuration::detail::__configuration, _prev);
    }

    ~TestCout() { configuration::detail::__configuration = std::move(_prev); }

    auto str() const { return _cout.str(); }

private:
    std::stringstream _cout;
    std::unique_ptr<Configuration> _prev;
};

TEST_SUITE_BEGIN("Tuple");

TEST_CASE("make") {
    auto t = tuple::make(1, true, 3.14);
    CHECK(tuple::has_value<0>(t));
    CHECK(tuple::has_value<1>(t));
    CHECK(tuple::has_value<2>(t));

    CHECK_EQ(tuple::get<0>(t), 1);
    CHECK_EQ(tuple::get<1>(t), true);
    CHECK_EQ(tuple::get<2>(t), 3.14);
}

TEST_CASE("make-from-optionals") {
    auto t = tuple::make_from_optionals(std::make_optional(1), std::optional<bool>(), std::make_optional(3.14));

    CHECK(tuple::has_value<0>(t));
    CHECK(! tuple::has_value<1>(t));
    CHECK(tuple::has_value<2>(t));

    CHECK_EQ(tuple::get<0>(t), 1);
    CHECK_THROWS_AS(tuple::get<1>(t), hilti::rt::UnsetTupleElement);
    CHECK_EQ(tuple::get<2>(t), 3.14);
}

TEST_CASE("assign") {
    auto t1 = tuple::make(1, true, 3.14);

    int i;
    bool b;
    double d;
    tuple::assign(std::tie(i, b, d), t1);
    CHECK_EQ(std::make_tuple(i, b, d), std::make_tuple(1, true, 3.14));

    auto t2 = tuple::make_from_optionals<int, bool, double>({1}, {true}, {});
    CHECK_THROWS_AS(tuple::assign(std::tie(i, b, d), t2), hilti::rt::UnsetTupleElement);
    ;
}

// Returns reference to element at given index using "tuple::elementOffset()".
template<size_t Idx, typename Dst, typename Tuple>
static const Dst& get_element_ref(const Tuple& t) {
    auto ptr = reinterpret_cast<const char*>(&t) + tuple::elementOffset<Tuple, Idx>();
    return *reinterpret_cast<const Dst*>(ptr);
}

TEST_CASE("elementOffset") {
    auto t1 = std::make_tuple(1);
    CHECK(get_element_ref<0, int>(t1) == 1);

    auto t2 = std::make_tuple(true, std::string("abc"), 3.14);
    CHECK(get_element_ref<0, bool>(t2) == true);
    CHECK(get_element_ref<1, std::string>(t2) == std::string("abc"));
    CHECK(get_element_ref<2, double>(t2) == 3.14);
}

TEST_CASE("wrap_expression") {
    CHECK_EQ(tuple::wrap_expression([&]() { return 42; }), std::make_optional(42));
    CHECK_EQ(tuple::wrap_expression([&]() -> int { throw AttributeNotSet(); }), std::optional<int>());
}

TEST_CASE("print") {
    SUBCASE("w/ newline") {
        TestCout cout;
        tuple::print(tuple::make("\x00\x01"_b, 0.5), true);
        CHECK_EQ(cout.str(), "\\x00\\x01, 0.5\n");
    }

    SUBCASE("w/o newline") {
        TestCout cout;
        tuple::print(tuple::make("\x00\x01"_b, 0.5), false);
        CHECK_EQ(cout.str(), "\\x00\\x01, 0.5");
    }
}

TEST_SUITE_END();
