// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, tuple, Equal)
HILTI_NODE_OPERATOR(hilti, tuple, Unequal)
HILTI_NODE_OPERATOR(hilti, tuple, Index)
HILTI_NODE_OPERATOR(hilti, tuple, Member)
HILTI_NODE_OPERATOR(hilti, tuple, CustomAssign)

} // namespace hilti::operator_
