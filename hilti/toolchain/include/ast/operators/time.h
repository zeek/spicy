// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, time, Equal)
HILTI_NODE_OPERATOR(hilti, time, Unequal)
HILTI_NODE_OPERATOR(hilti, time, SumInterval)
HILTI_NODE_OPERATOR(hilti, time, DifferenceTime)
HILTI_NODE_OPERATOR(hilti, time, DifferenceInterval)
HILTI_NODE_OPERATOR(hilti, time, Greater)
HILTI_NODE_OPERATOR(hilti, time, GreaterEqual)
HILTI_NODE_OPERATOR(hilti, time, Lower)
HILTI_NODE_OPERATOR(hilti, time, LowerEqual)
HILTI_NODE_OPERATOR(hilti, time, CtorSignedIntegerNs)
HILTI_NODE_OPERATOR(hilti, time, CtorSignedIntegerSecs)
HILTI_NODE_OPERATOR(hilti, time, CtorUnsignedIntegerNs)
HILTI_NODE_OPERATOR(hilti, time, CtorUnsignedIntegerSecs)
HILTI_NODE_OPERATOR(hilti, time, CtorRealSecs)
HILTI_NODE_OPERATOR(hilti, time, Seconds)
HILTI_NODE_OPERATOR(hilti, time, Nanoseconds)

} // namespace hilti::operator_
