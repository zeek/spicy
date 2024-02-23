// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, real, SignNeg)
HILTI_NODE_OPERATOR(hilti, real, Difference)
HILTI_NODE_OPERATOR(hilti, real, DifferenceAssign)
HILTI_NODE_OPERATOR(hilti, real, Division)
HILTI_NODE_OPERATOR(hilti, real, DivisionAssign)
HILTI_NODE_OPERATOR(hilti, real, Equal)
HILTI_NODE_OPERATOR(hilti, real, Greater)
HILTI_NODE_OPERATOR(hilti, real, GreaterEqual)
HILTI_NODE_OPERATOR(hilti, real, Lower)
HILTI_NODE_OPERATOR(hilti, real, LowerEqual)
HILTI_NODE_OPERATOR(hilti, real, Modulo)
HILTI_NODE_OPERATOR(hilti, real, Multiple)
HILTI_NODE_OPERATOR(hilti, real, MultipleAssign)
HILTI_NODE_OPERATOR(hilti, real, Power)
HILTI_NODE_OPERATOR(hilti, real, Sum)
HILTI_NODE_OPERATOR(hilti, real, SumAssign)
HILTI_NODE_OPERATOR(hilti, real, Unequal)
HILTI_NODE_OPERATOR(hilti, real, CastToUnsignedInteger)
HILTI_NODE_OPERATOR(hilti, real, CastToSignedInteger)
HILTI_NODE_OPERATOR(hilti, real, CastToTime)
HILTI_NODE_OPERATOR(hilti, real, CastToInterval)

} // namespace hilti::operator_
