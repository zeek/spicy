// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <exception>
#include <memory>
#include <sstream>
#include <type_traits>
#include <utility>

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

TEST_CASE("arrow") {
    CHECK_EQ(ValueReference<T>(42)->_x, 42);

    CHECK_THROWS_WITH_AS((void)ValueReference<T>::self(nullptr)->_x, "attempt to access null reference",
                         const NullReference&);
}

TEST_CASE("assign") {
    SUBCASE("from T") {
        ValueReference<int> ref;
        int x = 42;

        REQUIRE_NE(ref, x);

        ref = x;

        CHECK_EQ(ref, x);
    }

    SUBCASE("from ValueReference") {
        ValueReference<int> ref1;
        ValueReference<int> ref2(42);

        REQUIRE_NE(ref1, ref2);

        ref1 = ref2;

        CHECK_EQ(ref1, ref2);
    }
}

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

TEST_CASE("deref") {
    T x(42);
    SUBCASE("mutable") {
        CHECK_EQ(*ValueReference<T>(x), x);
        CHECK_THROWS_WITH_AS(*ValueReference<T>::self(nullptr), "attempt to access null reference",
                             const NullReference&);
    }

    SUBCASE("const") {
        {
            const auto ref = ValueReference<T>(x);
            CHECK_EQ(*ref, x);
        }

        {
            const auto ref = ValueReference<T>::self(nullptr);
            CHECK_THROWS_WITH_AS(*ref, "attempt to access null reference", const NullReference&);
        }
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

TEST_CASE("reset") {
    T x(42);

    ValueReference<T> ref;

    SUBCASE("owning") { ref = ValueReference<T>(x); }
    SUBCASE("non-owning") { ref = ValueReference<T>::self(&x); }

    REQUIRE(! ref.isNull());

    ref.reset();

    CHECK(ref.isNull());
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

TEST_CASE("arrow") {
    SUBCASE("mutable") {
        auto ref = ValueReference<int>(42);
        CHECK_EQ(StrongReference<int>(ref).operator->(), ref.get());

        CHECK_THROWS_WITH_AS(StrongReference<int>().operator->(), "attempt to access null reference",
                             const NullReference&);
    }

    SUBCASE("const") {
        const auto ref1 = ValueReference<int>(42);
        const auto ref2 = StrongReference<int>(ref1);
        const auto ref3 = StrongReference<int>();

        CHECK_EQ(ref2.operator->(), ref1.get());

        CHECK_THROWS_WITH_AS(ref3.operator->(), "attempt to access null reference", const NullReference&);
    }
}

TEST_CASE("bool") {
    CHECK(StrongReference<int>(42));
    CHECK_FALSE(StrongReference<int>());
}

TEST_CASE("construct") {
    SUBCASE("default") { CHECK(StrongReference<int>().isNull()); }

    SUBCASE("from T") {
        REQUIRE_FALSE(StrongReference<int>(42).isNull());
        CHECK_EQ(*StrongReference<int>(42), 42);
    }

    SUBCASE("from ValueReference") {
        const auto ref = ValueReference<int>(42);
        REQUIRE_EQ(*ref, 42);
        CHECK_EQ(StrongReference<int>(ref).get(), ref.get());
    }

    SUBCASE("copy") {
        const auto ref1 = StrongReference<int>(42);
        const auto ref2 = StrongReference<int>(ref1);
        CHECK_EQ(ref1, ref2);
        CHECK_EQ(ref1.get(), ref2.get());
    }

    SUBCASE("move") {
        const int x = 42;
        auto ref1 = StrongReference<int>(x);
        const auto ptr = ref1.get();

        const auto ref2 = StrongReference<int>(std::move(ref1));
        CHECK_EQ(*ref2, 42);
        CHECK_EQ(ref2.get(), ptr);
    }
}

TEST_CASE("deref") {
    SUBCASE("mutable") {
        CHECK_EQ(*StrongReference<int>(42), 42);
        CHECK_THROWS_WITH_AS(*StrongReference<int>(), "attempt to access null reference", const NullReference&);
    }

    SUBCASE("const") {
        auto ref1 = StrongReference<int>(42);
        auto ref2 = StrongReference<int>();

        CHECK_EQ(*ref1, 42);
        CHECK_THROWS_WITH_AS(*ref2, "attempt to access null reference", const NullReference&);
    }
}

TEST_CASE("derefAsValue") {
    SUBCASE("unset") { CHECK_EQ(StrongReference<int>().derefAsValue().asSharedPtr(), nullptr); }

    SUBCASE("set") {
        const auto ref = ValueReference<int>();
        CHECK_EQ(StrongReference<int>(ref).derefAsValue().get(), ref.get());
    }
}

TEST_CASE("isNull") {
    CHECK(StrongReference<int>().isNull());
    CHECK_FALSE(StrongReference<int>(42).isNull());

    CHECK(StrongReference<int>(ValueReference<int>(std::shared_ptr<int>())).isNull());
    CHECK_FALSE(StrongReference<int>(ValueReference<int>(std::make_shared<int>(42))).isNull());
}

TEST_CASE("reset") {
    const auto ref1 = ValueReference<int>(42);
    REQUIRE_FALSE(ref1.isNull());

    auto ref2 = StrongReference<int>(ref1);
    REQUIRE_FALSE(ref2.isNull());
    REQUIRE_EQ(ref1.get(), ref2.get());

    ref2.reset();
    CHECK_FALSE(ref1.isNull());
    CHECK(ref2.isNull());
}

TEST_SUITE_END();
