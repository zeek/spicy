// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/extension-points.h>

#include <spicy/rt/sink.h>

using namespace hilti::rt;
using namespace spicy::rt;

TEST_SUITE_BEGIN("Sink");

TEST_CASE("to_string") { CHECK_EQ(to_string(sink::ReassemblerPolicy::First), "sink::ReassemblerPolicy::First"); }

TEST_SUITE_END();
