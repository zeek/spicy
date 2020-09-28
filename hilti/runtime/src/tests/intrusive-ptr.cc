// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/intrusive-ptr.h>

// The IntrusivePtr class is adapted from Zeek. We only test basic
// functionality and extensions here.

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

TEST_SUITE_END();
