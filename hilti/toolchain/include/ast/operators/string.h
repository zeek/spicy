// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, string, Equal)
HILTI_NODE_OPERATOR(hilti, string, Unequal)
HILTI_NODE_OPERATOR(hilti, string, Size)
HILTI_NODE_OPERATOR(hilti, string, Sum)
HILTI_NODE_OPERATOR(hilti, string, SumAssign)
HILTI_NODE_OPERATOR(hilti, string, Modulo)
HILTI_NODE_OPERATOR(hilti, string, Encode)

} // namespace hilti::operator_
