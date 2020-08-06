// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <exception>
#include <memory>
#include <sstream>
#include <type_traits>

#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/struct.h>

using namespace hilti::rt;

struct T : public hilti::rt::trait::isStruct, hilti::rt::Controllable<T> {
    /*implicit*/ T(int x = 0) : _x(x) {}
    int _x;

    void foo(int y) {
        // Ensure we can reconstruct a value ref from "this".
        auto self = ValueReference<T>::self(this);
        CHECK_EQ(_x, y);
        CHECK_EQ(self->_x, y);
    }

    friend bool operator==(const T& a, const T& b) { return a._x == b._x; }
};

namespace hilti::rt::detail::adl {

inline std::string to_string(int x, tag /*unused*/) { return hilti::rt::fmt("%d", x); }

inline std::string to_string(const T& x, tag /*unused*/) { return hilti::rt::fmt("x=%d", x._x); }

} // namespace hilti::rt::detail::adl

TEST_SUITE_BEGIN("ValueReference");

TEST_CASE("asSharedPtr") {
    SUBCASE("owning") {
        T x(42);

        REQUIRE(ValueReference<T>(x).asSharedPtr());
        CHECK_EQ(*ValueReference<T>(x).asSharedPtr(), x);
    }

    SUBCASE("non-owning") {
        auto ptr = std::make_shared<T>(42);

        REQUIRE(ValueReference<T>::self(ptr.get()).asSharedPtr());
        CHECK_EQ(*ValueReference<T>::self(ptr.get()).asSharedPtr(), *ptr);

        CHECK_THROWS_WITH_AS(ValueReference<T>::self(nullptr).asSharedPtr(), "unexpected state of value reference",
                             const IllegalReference&);

        T x(42);
        CHECK_THROWS_WITH_AS(ValueReference<T>::self(&x).asSharedPtr(), "reference to non-heap instance",
                             const IllegalReference&);
    }
}

TEST_CASE_TEMPLATE("construct", U, int, T) {
    SUBCASE("default") {
        const ValueReference<U> ref;
        CHECK_EQ(*ref, U());
    }

    const U x(42);

    SUBCASE("from value") {
        ValueReference<U> ref(x);
        CHECK_EQ(*ref, x);
    }

    SUBCASE("from ptr") {
        const auto ptr = std::make_shared<U>(x);
        ValueReference<U> ref(ptr);
        CHECK_EQ(*ref, x);
    }

    SUBCASE("copy") {
        SUBCASE("other initialized") {
            const ValueReference<U> ref1(x);
            const ValueReference<U> ref2(ref1);
            CHECK_EQ(*ref1, *ref2);
            CHECK_NE(ref1.get(), ref2.get());
        }

        SUBCASE("other uninitialized") {
            // This test only makes sense if `U` is a `Controllable`, i.e., for `T` for our instantiations.
            if constexpr ( std::is_same_v<U, T> ) {
                const auto ref1 = ValueReference<U>::self(nullptr);
                REQUIRE_EQ(ref1.get(), nullptr);

                const ValueReference<U> ref2(ref1);
                CHECK_EQ(ref2.get(), nullptr);
            }
        }
    }

    SUBCASE("move") {
        ValueReference<U> ref1{x};
        REQUIRE_NE(ref1.asSharedPtr(), nullptr);

        const ValueReference<U> ref2(std::move(ref1));
        CHECK_EQ(*ref2, x);
        CHECK_EQ(ref1.asSharedPtr(), nullptr);
    }
}

TEST_CASE("get") {
    T x(42);

    SUBCASE("valid value") {
        CHECK_NE(ValueReference<T>().get(), nullptr);

        REQUIRE(ValueReference<T>(x).get());
        CHECK_EQ(*ValueReference<T>(x).get(), x);
        CHECK_NE(ValueReference<T>(x).get(), nullptr);

        CHECK_EQ(ValueReference<T>::self(&x).get(), &x);
    }

    SUBCASE("invalid value") { CHECK_EQ(ValueReference<T>::self(nullptr).get(), nullptr); }
}

TEST_CASE("isNull") {
    T x(42);

    CHECK_FALSE(ValueReference<T>().isNull());
    CHECK_FALSE(ValueReference<T>(x).isNull());
    CHECK_FALSE(ValueReference<T>::self(&x).isNull());
    CHECK(ValueReference<T>::self(nullptr).isNull());
}

TEST_CASE("self") {
    T x1(0);

    auto self = ValueReference<T>::self(&x1);

    self->_x = 42;
    CHECK_EQ(self->_x, 42);
    CHECK_EQ(x1._x, 42);

    CHECK_THROWS_WITH_AS(StrongReference<T>{self}, "reference to non-heap instance", const IllegalReference&);
    CHECK_THROWS_WITH_AS(WeakReference<T>{self}, "reference to non-heap instance", const IllegalReference&);
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

TEST_SUITE_BEGIN("StrongReference");

TEST_CASE_TEMPLATE("construct", U, int, T) {
    StrongReference<U> x0;
    CHECK_FALSE(x0);

    StrongReference<U> x1(42);
    REQUIRE(x1);
    CHECK_EQ(*x1, 42);

    StrongReference<U> x2(x1);
    REQUIRE(x2);
    CHECK_EQ(*x2, 42);

    *x1 = 21;
    CHECK_EQ(*x1, 21);
    CHECK_EQ(*x2, 21);

    ValueReference<U> v1{1};
    ValueReference<U> v2{2};

    x1 = v1;
    x2 = x1;
    v1 = v2;

    CHECK_EQ(*x1, 2);
    CHECK_EQ(*v1, 2);
    CHECK_EQ(*x2, 2);
    CHECK_EQ(*v2, 2);
}

TEST_SUITE_END();
