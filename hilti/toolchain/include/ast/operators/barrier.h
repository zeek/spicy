// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/barrier.h>

namespace hilti::operator_ {

STANDARD_KEYWORD_CTOR(barrier, Ctor, "barrier", type::Barrier(type::Wildcard()),
                      type::UnsignedInteger(type::Wildcard()),
                      "Creates a barrier that will wait for the given number of parties.");
}
