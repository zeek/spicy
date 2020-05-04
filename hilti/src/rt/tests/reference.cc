// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <exception>
#include <sstream>

#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/struct.h>

using namespace hilti::rt;

struct T : public hilti::rt::trait::isStruct, hilti::rt::Controllable<T> {
    int x;

    void foo(int y) {
        // Ensure we can reconstruct a value ref from "this".
        auto self = ValueReference<T>::self(this);
        REQUIRE(x == y);
        REQUIRE(self->x == y);
    }
};

namespace hilti::rt::detail::adl {

inline std::string to_string(int x, tag /*unused*/) { return hilti::rt::fmt("%d", x); }

inline std::string to_string(const T& x, tag /*unused*/) { return hilti::rt::fmt("x=%d", x.x); }

} // namespace hilti::rt::detail::adl

TEST_SUITE_BEGIN("reference");

TEST_CASE("value-reference-int") {
    using T = int;

    ValueReference<T> x1;
    REQUIRE(*x1 == 0);

    ValueReference<T> x2(42);
    REQUIRE(*x2 == 42);

    ValueReference<T> x3(x2);
    REQUIRE(*x3 == 42);

    x3 = 21;
    REQUIRE(*x3 == 21);
    REQUIRE(*x2 == 42);

    ValueReference<T> x4(std::move(x3));
    REQUIRE(*x4 == 21);
    REQUIRE(x3.isNull());

    ValueReference<T> x5;
    x5 = std::move(x4);
    REQUIRE(*x5 == 21);
    REQUIRE(x4.isNull());
}

TEST_CASE("value-reference-struct") {
    ValueReference<T> x1;
    REQUIRE(x1->x == 0);

    T t;
    t.x = 42;
    ValueReference<T> x2(t);
    REQUIRE(x2->x == 42);

    x2->x = 21;
    x2->foo(21);

    x2->x = 42;
    x2->foo(42);
}

TEST_CASE("value-reference-struct-self") {
    T x1;

    auto self = ValueReference<T>::self(&x1);

    self->x = 42;
    REQUIRE(self->x == 42);
    REQUIRE(x1.x == 42);

    REQUIRE_THROWS(StrongReference<T>{self});
    REQUIRE_THROWS(WeakReference<T>{self});
}


TEST_CASE("strong-reference") {
    using T = int;

    StrongReference<T> x0;
    REQUIRE(! x0);

    StrongReference<T> x1(42);
    REQUIRE(x1);
    REQUIRE(*x1 == 42);

    StrongReference<T> x2(x1);
    REQUIRE(x2);
    REQUIRE(*x2 == 42);

    *x1 = 21;
    REQUIRE(*x1 == 21);
    REQUIRE(*x2 == 21);

    ValueReference<T> v1{1};
    ValueReference<T> v2{2};

    x1 = v1;
    x2 = x1;
    v1 = v2;

    REQUIRE(*x1 == 2);
    REQUIRE(*v1 == 2);
    REQUIRE(*x2 == 2);
    REQUIRE(*v2 == 2);
}

struct Foo;

struct Test : hilti::rt::Controllable<Test> {
    std::optional<hilti::rt::ValueReference<Foo>> f;
};

struct Foo : hilti::rt::Controllable<Foo> {
    hilti::rt::WeakReference<Test> t;
};

TEST_CASE("cyclic") {
    hilti::rt::ValueReference<Test> test;
    auto __test = hilti::rt::ValueReference<Test>::self(&*test);
    hilti::rt::ValueReference<Foo> __foo;

    __foo->t = __test;
    test->f = (*__foo);
}

TEST_SUITE_END();
