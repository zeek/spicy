// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(bitfield, Member)
HILTI_NODE_OPERATOR(bitfield, HasMember)

} // namespace hilti::operator_
