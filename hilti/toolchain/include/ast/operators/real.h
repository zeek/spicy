// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(real, SignNeg)
HILTI_NODE_OPERATOR(real, Difference)
HILTI_NODE_OPERATOR(real, DifferenceAssign)
HILTI_NODE_OPERATOR(real, Division)
HILTI_NODE_OPERATOR(real, DivisionAssign)
HILTI_NODE_OPERATOR(real, Equal)
HILTI_NODE_OPERATOR(real, Greater)
HILTI_NODE_OPERATOR(real, GreaterEqual)
HILTI_NODE_OPERATOR(real, Lower)
HILTI_NODE_OPERATOR(real, LowerEqual)
HILTI_NODE_OPERATOR(real, Modulo)
HILTI_NODE_OPERATOR(real, Multiple)
HILTI_NODE_OPERATOR(real, MultipleAssign)
HILTI_NODE_OPERATOR(real, Power)
HILTI_NODE_OPERATOR(real, Sum)
HILTI_NODE_OPERATOR(real, SumAssign)
HILTI_NODE_OPERATOR(real, Unequal)
HILTI_NODE_OPERATOR(real, CastToUnsignedInteger)
HILTI_NODE_OPERATOR(real, CastToSignedInteger)
HILTI_NODE_OPERATOR(real, CastToTime)
HILTI_NODE_OPERATOR(real, CastToInterval)

} // namespace hilti::operator_
