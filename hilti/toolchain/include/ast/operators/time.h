// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(time, Equal)
HILTI_NODE_OPERATOR(time, Unequal)
HILTI_NODE_OPERATOR(time, SumInterval)
HILTI_NODE_OPERATOR(time, DifferenceTime)
HILTI_NODE_OPERATOR(time, DifferenceInterval)
HILTI_NODE_OPERATOR(time, Greater)
HILTI_NODE_OPERATOR(time, GreaterEqual)
HILTI_NODE_OPERATOR(time, Lower)
HILTI_NODE_OPERATOR(time, LowerEqual)
HILTI_NODE_OPERATOR(time, CtorSignedIntegerNs)
HILTI_NODE_OPERATOR(time, CtorSignedIntegerSecs)
HILTI_NODE_OPERATOR(time, CtorUnsignedIntegerNs)
HILTI_NODE_OPERATOR(time, CtorUnsignedIntegerSecs)
HILTI_NODE_OPERATOR(time, CtorRealSecs)
HILTI_NODE_OPERATOR(time, Seconds)
HILTI_NODE_OPERATOR(time, Nanoseconds)

} // namespace hilti::operator_
