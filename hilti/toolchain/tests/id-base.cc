// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
#include <doctest/doctest.h>

#include <string>

#include <hilti/autogen/config.h>
#include <hilti/base/id-base.h>


using namespace hilti;

std::string normalizeID(std::string id) { return id; }

class ID : public detail::IDBase<ID, normalizeID> {
    using Base = detail::IDBase<ID, normalizeID>;
    using Base::IDBase;
};

TEST_SUITE_BEGIN("IDBase");

TEST_CASE("concat") {
    CHECK_EQ(ID("a"), ID("a"));
    CHECK_EQ(ID("a") + ID("b"), ID("a::b"));
    CHECK_EQ(ID("a") + ID("b") + ID("c"), ID("a::b::c"));
    CHECK_EQ(ID() + ID("b"), ID("b"));
    CHECK_EQ(ID("a") + ID(), ID("a"));
}

TEST_SUITE_END();
