// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/exception.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/reference.h>

#include <spicy/rt/parsed-unit.h>

using namespace hilti::rt;
using namespace spicy::rt;

// Pre-generated type info for `value_ref<uint64_t>`.
const ::hilti::rt::TypeInfo ti_value_ref_uint_64 =
    {{},
     "value_ref<uint<64>>",
     [](const void* self) {
         return hilti::rt::to_string(
             *reinterpret_cast<const ::hilti::rt::ValueReference<::hilti::rt::integer::safe<uint64_t>>*>(self));
     },
     new ::hilti::rt::type_info::ValueReference(&::hilti::rt::type_info::uint64,
                                                ::hilti::rt::type_info::ValueReference::accessor<
                                                    ::hilti::rt::integer::safe<uint64_t>>())};

TEST_SUITE_BEGIN("ParsedUnit");

TEST_CASE("get") {
    ParsedUnit p;

    SUBCASE("uninitialized") { CHECK_THROWS_WITH_AS(p.get<int>(), "parsed unit not set", const NullReference&); }

    SUBCASE("initialized") {
        const auto ref = ValueReference<uint64_t>(42);
        ParsedUnit::initialize(p, ref, &ti_value_ref_uint_64);

        CHECK_EQ(p.get<uint64_t>(), 42);
    }
}

TEST_CASE("initialize") {
    ParsedUnit p;
    const auto ref = ValueReference<uint64_t>(42);
    ParsedUnit::initialize(p, ref, &ti_value_ref_uint_64);

    CHECK_EQ(p.get<uint64_t>(), 42);
}

TEST_CASE("reset") {
    ParsedUnit p;

    SUBCASE("uninitialized") {}

    SUBCASE("initialized") {
        const auto ref = ValueReference<uint64_t>(42);
        ParsedUnit::initialize(p, ref, &ti_value_ref_uint_64);

        CHECK_NOTHROW(p.get<uint64_t>());
    }

    p.reset();
    CHECK_THROWS_WITH_AS(p.get<int>(), "parsed unit not set", const NullReference&);
}

TEST_CASE("value") {
    ParsedUnit p;

    SUBCASE("uninitialized") { CHECK_THROWS_WITH_AS(p.value(), "parsed unit not set", const NullReference&); }

    SUBCASE("initialized") {
        const auto ref = ValueReference<uint64_t>(42);
        ParsedUnit::initialize(p, ref, &ti_value_ref_uint_64);

        CHECK_EQ(p.value(), type_info::Value(ref.get(), &ti_value_ref_uint_64, p));
    }
}

TEST_CASE("to_string") {
    ParsedUnit p;

    CHECK_EQ(to_string(p), "<parsed unit>");

    std::stringstream x;
    x << p;
    CHECK_EQ(x.str(), "<parsed unit>");
}

TEST_SUITE_END();
