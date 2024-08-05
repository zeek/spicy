// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(string, Equal)
HILTI_NODE_OPERATOR(string, Unequal)
HILTI_NODE_OPERATOR(string, Size)
HILTI_NODE_OPERATOR(string, Sum)
HILTI_NODE_OPERATOR(string, SumAssign)
HILTI_NODE_OPERATOR(string, Modulo)
HILTI_NODE_OPERATOR(string, Encode)
HILTI_NODE_OPERATOR(string, Split)
HILTI_NODE_OPERATOR(string, Split1)
HILTI_NODE_OPERATOR(string, StartsWith)
HILTI_NODE_OPERATOR(string, LowerCase)
HILTI_NODE_OPERATOR(string, UpperCase)

} // namespace hilti::operator_
