// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/type-info.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("TypeInfo");

/* HILTI code to generate the type information used in this test:

module Test {

type X = struct {
    int<32> i;
    string s;
    Y y;
};

type Y = struct {
    bool b;
    real r;
};

*/

// Copied from output of hiltic.
namespace __hlt::type_info {
namespace {
extern const hilti::rt::TypeInfo __ti_Test_X;
extern const hilti::rt::TypeInfo __ti_Test_Y;
} // namespace
} // namespace __hlt::type_info

namespace Test {

// Reduced declaration of the struct types, trusting that ours will match the
// layout coming out of HILTI ...
struct Y {
    hilti::rt::Bool b;
    double r;
};

struct X {
    hilti::rt::integer::safe<int32_t> i;
    std::string s;
    Y y;
};
} // namespace Test

// Copied from output of hiltic.
namespace __hlt::type_info {
namespace {
const hilti::rt::TypeInfo __ti_Test_X =
    {"Test::X", "Test::X", nullptr,
     new hilti::rt::type_info::Struct(std::vector<hilti::rt::type_info::struct_::Field>(
         {hilti::rt::type_info::struct_::Field{"i", &hilti::rt::type_info::int32, offsetof(Test::X, i), false, false,
                                               true},
          hilti::rt::type_info::struct_::Field{"s", &hilti::rt::type_info::string, offsetof(Test::X, s), false, false,
                                               true},
          hilti::rt::type_info::struct_::Field{"y", &type_info::__ti_Test_Y, offsetof(Test::X, y), false, false,
                                               true}}))};
const hilti::rt::TypeInfo __ti_Test_Y =
    {"Test::Y", "Test::Y", nullptr,
     new hilti::rt::type_info::Struct(std::vector<hilti::rt::type_info::struct_::Field>(
         {hilti::rt::type_info::struct_::Field{"b", &hilti::rt::type_info::bool_, offsetof(Test::Y, b), false, false,
                                               true},
          hilti::rt::type_info::struct_::Field{"r", &hilti::rt::type_info::real, offsetof(Test::Y, r), false, false,
                                               true}}))};
} // namespace
} // namespace __hlt::type_info

TEST_CASE("traverse structs") {
    // Check that we can traverse the structs and get expected values.

    auto sx = StrongReference<Test::X>({42, "foo", Test::Y{true, 3.14}});
    auto p = type_info::value::Parent(sx);
    auto v = type_info::Value(&*sx, &__hlt::type_info::__ti_Test_X, p);

    auto x = type_info::value::auxType<type_info::Struct>(v)->iterate(v);
    auto xi = x.begin();
    auto xf1 = type_info::value::auxType<type_info::SignedInteger<int32_t>>(xi->second)->get(xi->second);

    CHECK(xf1 == 42);
    xi++;

    auto xf2 = type_info::value::auxType<type_info::String>(xi->second)->get(xi->second);
    CHECK(xf2 == std::string("foo"));
    xi++;

    auto y = type_info::value::auxType<type_info::Struct>(xi->second)->iterate(xi->second);
    auto yi = y.begin();

    auto yf1 = type_info::value::auxType<type_info::Bool>(yi->second)->get(yi->second);
    CHECK(yf1 == true);
    yi++;

    auto yf2 = type_info::value::auxType<type_info::Real>(yi->second)->get(yi->second);
    CHECK(yf2 == 3.14);
    yi++;

    xi++;
    CHECK(yi == y.end());
    CHECK(xi == x.end());
}

TEST_CASE("life-time") {
    // Check that we catch when values become inaccessible because of the
    // associated parent going away.
    Test::Y y{true, 3.14};

    auto x = StrongReference<Test::X>({42, "foo", y});
    auto p = type_info::value::Parent(x);
    auto v = type_info::Value(&*x, &__hlt::type_info::__ti_Test_X, p);

    // v is valid
    v.pointer();

    p = type_info::value::Parent();

    // Now invalid.
    CHECK_THROWS_WITH_AS(v.pointer(), "type info value expired", const InvalidValue&);
}

TEST_CASE("no parent") {
    Test::Y y{true, 3.14};

    auto x = StrongReference<Test::X>({42, "foo", y});
    auto p = type_info::value::Parent(x);
    auto v = type_info::Value(&*x, &__hlt::type_info::__ti_Test_X); // no parent

    CHECK_EQ(v.pointer(), &*x); // access to the value works even without parent
}

TEST_CASE("internal fields") {
    struct A {
        integer::safe<int32_t> f1;
        std::string f2;
        bool __internal;
    };

    const TypeInfo ti = {"A", "A", nullptr,
                         new type_info::Struct(
                             {type_info::struct_::Field{"f1", &type_info::int32, offsetof(A, f1), false, false, true},
                              type_info::struct_::Field{"f2", &type_info::string, offsetof(A, f2), false, false, true},
                              type_info::struct_::Field{"__internal", &type_info::bool_, offsetof(A, __internal), true,
                                                        false, true}})};

    auto sx = StrongReference<A>({42, "foo", true});
    auto p = type_info::value::Parent(sx);
    auto v = type_info::Value(&*sx, &ti, p);

    const auto* const s = type_info::value::auxType<type_info::Struct>(v);

    CHECK_EQ(s->fields().size(), 2U);
    CHECK_EQ(s->fields(false).size(), 2U);
    CHECK_EQ(s->fields(true).size(), 3U);

    CHECK_EQ(s->iterate(v).size(), 2U);
    CHECK_EQ(s->iterate(v, false).size(), 2U);
    CHECK_EQ(s->iterate(v, true).size(), 3U);
}

TEST_CASE("anonymous fields") {
    struct A {
        std::string f1;
    };

    const TypeInfo ti = {"A", "A", nullptr,
                         new type_info::Struct(
                             {type_info::struct_::Field{"f1", &type_info::int32, offsetof(A, f1), false, true, true}})};

    auto sx = StrongReference<A>({"foo"});
    auto p = type_info::value::Parent(sx);
    auto v = type_info::Value(&*sx, &ti, p);

    const auto* const s = type_info::value::auxType<type_info::Struct>(v);

    CHECK_EQ(s->fields().size(), 1U);
    CHECK(s->fields()[0].get().isAnonymous());
    CHECK(s->fields()[0].get().isEmitted());
}

TEST_CASE("no-emit fields") {
    struct A {
        std::string f1;
    };

    const TypeInfo ti = {"A", "A", nullptr,
                         new type_info::Struct({type_info::struct_::Field{"f1", &type_info::int32, offsetof(A, f1),
                                                                          false, false, false}})};

    auto sx = StrongReference<A>({"foo"});
    auto p = type_info::value::Parent(sx);
    auto v = type_info::Value(&*sx, &ti, p);

    const auto* const s = type_info::value::auxType<type_info::Struct>(v);

    CHECK_EQ(s->fields().size(), 1U);
    CHECK(! s->fields()[0].get().isEmitted());

    // We shouldn't see this field when iterating.
    int count = std::ranges::distance(type_info::value::auxType<type_info::Struct>(v)->iterate(v));
    CHECK_EQ(count, 0);
}

TEST_SUITE_END();
