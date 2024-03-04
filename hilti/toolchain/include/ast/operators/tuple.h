// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(tuple, Equal)
HILTI_NODE_OPERATOR(tuple, Unequal)
HILTI_NODE_OPERATOR(tuple, Index)
HILTI_NODE_OPERATOR(tuple, Member)
HILTI_NODE_OPERATOR(tuple, CustomAssign)

} // namespace hilti::operator_
