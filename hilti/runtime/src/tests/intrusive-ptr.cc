// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <utility>

#include <hilti/rt/intrusive-ptr.h>

// The IntrusivePtr class is adapted from Zeek. We only test basic
// functionality and extensions here.

// Some versions of GCC have trouble following the internal state of
// `IntrusivePtr` and might report frees of non-heap objects, even though the
// code would not be called. Silence this warning (and accommodate for either
// Clang or GCC not knowing that warning).
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#pragma GCC diagnostic ignored "-Wfree-nonheap-object"

using namespace hilti::rt;

TEST_SUITE_BEGIN("IntrusivePtr");

class Managed : public intrusive_ptr::ManagedObject {
public:
    Managed() { ++instances; }
    ~Managed() { --instances; }
    static inline int instances = 0;
};

using ManagedPtr = IntrusivePtr<Managed>;

TEST_CASE("managed objects") {
    CHECK_EQ(Managed::instances, 0);

    auto p1 = make_intrusive<Managed>();
    CHECK_EQ(Managed::instances, 1);

    ManagedPtr p2 = p1;
    CHECK_EQ(Managed::instances, 1);

    p1 = nullptr;
    CHECK_EQ(Managed::instances, 1);

    p2 = nullptr;
    CHECK_EQ(Managed::instances, 0);
}

struct TestObject : intrusive_ptr::ManagedObject {
    static uint64_t instances;
    TestObject() { ++instances; }
    TestObject(int _i) : i(_i) { ++instances; }

    ~TestObject() { --instances; }

    int i = 0;
};

uint64_t TestObject::instances = 0;

struct TestObject2 : TestObject {
    using TestObject::TestObject;
};

TEST_CASE("ManagedObject") {
    SUBCASE("valid object") {
        auto* obj = new TestObject();
        REQUIRE_EQ(TestObject::instances, 1);

        intrusive_ptr::Ref(obj);
        CHECK_EQ(TestObject::instances, 1);

        intrusive_ptr::Unref(obj);
        CHECK_EQ(TestObject::instances, 1);

        intrusive_ptr::Unref(obj);
        CHECK_EQ(TestObject::instances, 0);

        // Cannot call `Unref` again as `obj` is now invalid.
    }

    SUBCASE("null") {
        TestObject* obj = nullptr;
        intrusive_ptr::Ref(obj);
        CHECK_EQ(TestObject::instances, 0);

        intrusive_ptr::Unref(obj);
        CHECK_EQ(TestObject::instances, 0);

        intrusive_ptr::Unref(obj);
        CHECK_EQ(TestObject::instances, 0);
    }
}

TEST_CASE("ctr") {
    REQUIRE_EQ(TestObject::instances, 0);

    SUBCASE("default") {
        IntrusivePtr<TestObject> x;
        CHECK_EQ(TestObject::instances, 0);
        CHECK_FALSE(x);
    }

    SUBCASE("null") {
        IntrusivePtr<TestObject> x(nullptr);
        CHECK_EQ(TestObject::instances, 0);
        CHECK_FALSE(x);
    }

    SUBCASE("adopt") {
        {
            IntrusivePtr<TestObject> x(intrusive_ptr::AdoptRef{}, new TestObject);
            CHECK_EQ(TestObject::instances, 1);
        }
        CHECK_EQ(TestObject::instances, 0);
    }

    SUBCASE("newref") {
        {
            TestObject obj;
            IntrusivePtr<TestObject> x(intrusive_ptr::NewRef{}, &obj);
            CHECK_EQ(TestObject::instances, 1);
        }
        CHECK_EQ(TestObject::instances, 0);
    }
}

TEST_CASE("move ctr") {
    REQUIRE_EQ(TestObject::instances, 0);

    TestObject obj;
    IntrusivePtr<TestObject> x1(intrusive_ptr::NewRef{}, &obj);
    REQUIRE_EQ(TestObject::instances, 1);

    IntrusivePtr<TestObject> x2(std::move(x1));
    CHECK_EQ(TestObject::instances, 1);

    // NOLINTNEXTLINE(bugprone-use-after-move, clang-analyzer-cplusplus.Move)
    CHECK_FALSE(x1.get());
    CHECK(x2.get());
}

TEST_CASE("copy ctr") {
    REQUIRE_EQ(TestObject::instances, 0);

    TestObject obj;
    IntrusivePtr<TestObject> x1(intrusive_ptr::NewRef{}, &obj);
    REQUIRE_EQ(TestObject::instances, 1);

    const IntrusivePtr<TestObject>& x2(x1);
    CHECK_EQ(TestObject::instances, 1);

    CHECK_EQ(x1.get(), x2.get());
}

TEST_CASE("conversion") {
    REQUIRE_EQ(TestObject::instances, 0);
    REQUIRE_EQ(TestObject::instances, 0);

    TestObject2 obj2;
    IntrusivePtr<TestObject> x2(intrusive_ptr::NewRef{}, &obj2);
    REQUIRE_EQ(TestObject::instances, 1);

    static_assert(std::is_convertible_v<TestObject2*, TestObject*>);

    const IntrusivePtr<TestObject>& x(x2);

    // The new ptr refers to the same object.
    CHECK_EQ(TestObject::instances, 1);

    // The constructed from ptr remains valid.
    CHECK(x2.get());

    CHECK_EQ(x.get(), x2.get());
}

TEST_CASE("dtr") {
    // Already covered by ctr.adopt above.
}

TEST_CASE("swap") {
    TestObject obj1;
    TestObject obj2;

    IntrusivePtr<TestObject> x1(intrusive_ptr::NewRef{}, &obj1);
    IntrusivePtr<TestObject> x2(intrusive_ptr::NewRef{}, &obj2);

    REQUIRE_EQ(x1.get(), &obj1);
    REQUIRE_EQ(x2.get(), &obj2);

    SUBCASE("member function") { x1.swap(x2); }
    SUBCASE("free function") { swap(x1, x2); }

    REQUIRE_EQ(x1.get(), &obj2);
    REQUIRE_EQ(x2.get(), &obj1);
}

TEST_CASE("release") {
    TestObject obj;
    IntrusivePtr<TestObject> x(intrusive_ptr::NewRef{}, &obj);
    REQUIRE(x.get());
    REQUIRE_EQ(x.get(), &obj);

    auto* release = x.release();
    CHECK_EQ(release, &obj);
    CHECK_FALSE(x.get());
}

TEST_CASE("get") {
    CHECK_FALSE(IntrusivePtr<TestObject>(nullptr).get());

    TestObject obj;
    IntrusivePtr<TestObject> x(intrusive_ptr::NewRef{}, &obj);
    CHECK_EQ(x.get(), &obj);
}

TEST_CASE("arrow") {
    TestObject obj;
    IntrusivePtr<TestObject> x(intrusive_ptr::NewRef{}, &obj);
    CHECK_EQ(&x->i, &obj.i);
}

TEST_CASE("deref") {
    TestObject obj;
    IntrusivePtr<TestObject> x(intrusive_ptr::NewRef{}, &obj);
    REQUIRE(x);

    CHECK_EQ(&*x, &obj);
}

TEST_CASE("bool") {
    CHECK(IntrusivePtr<TestObject>(intrusive_ptr::AdoptRef{}, new TestObject));
    CHECK_FALSE(IntrusivePtr<TestObject>(intrusive_ptr::NewRef{}, nullptr));
    CHECK_FALSE(IntrusivePtr<TestObject>(nullptr));
}

TEST_CASE("not") {
    CHECK(! ! IntrusivePtr<TestObject>(intrusive_ptr::AdoptRef{}, new TestObject));
    CHECK_FALSE(! ! IntrusivePtr<TestObject>(intrusive_ptr::NewRef{}, nullptr));
    CHECK_FALSE(! ! IntrusivePtr<TestObject>(nullptr));
}

TEST_CASE("make_intrusive") {
    SUBCASE("w/o args") {
        auto x = make_intrusive<TestObject>();
        REQUIRE(x);
        CHECK_EQ(x->i, 0);
    }

    SUBCASE("w/ args") {
        auto x = make_intrusive<TestObject>(42);
        REQUIRE(x);
        CHECK_EQ(x->i, 42);
    }
}

TEST_CASE("cast_intrusive") {
    const auto x1 = make_intrusive<TestObject2>(2);
    REQUIRE_EQ(x1->i, 2);

    auto x2 = cast_intrusive<TestObject>(x1);
    CHECK(std::is_same_v<decltype(x2), IntrusivePtr<TestObject>>);
    CHECK_EQ(x2->i, x1->i);
}

TEST_CASE("equality") {
    auto x1 = make_intrusive<TestObject>(1);
    auto nil = IntrusivePtr<TestObject>(nullptr);

    // Equality is equality of pointed to value, not of wrapped value itself.
    CHECK_NE(x1, make_intrusive<TestObject>(x1->i));
    CHECK_EQ(x1, x1);

    CHECK_EQ(nil, nil);
    CHECK_EQ(nil, nullptr);
    CHECK_EQ(nullptr, nil);
    CHECK_NE(x1, nullptr);
    CHECK_NE(nullptr, x1);

    CHECK_EQ(x1, x1.get());
    CHECK_EQ(x1.get(), x1);
    CHECK_EQ(nil, nil.get());

    CHECK_EQ(x1, cast_intrusive<TestObject2>(x1));
    CHECK_EQ(cast_intrusive<TestObject2>(x1), x1);
    CHECK_NE(x1, cast_intrusive<TestObject2>(nil));
    CHECK_NE(cast_intrusive<TestObject2>(nil), x1);
}

TEST_SUITE_END();
