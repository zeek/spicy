// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, interval, Equal)
HILTI_NODE_OPERATOR(hilti, interval, Unequal)
HILTI_NODE_OPERATOR(hilti, interval, Sum)
HILTI_NODE_OPERATOR(hilti, interval, Difference)
HILTI_NODE_OPERATOR(hilti, interval, Greater)
HILTI_NODE_OPERATOR(hilti, interval, GreaterEqual)
HILTI_NODE_OPERATOR(hilti, interval, Lower)
HILTI_NODE_OPERATOR(hilti, interval, LowerEqual)
HILTI_NODE_OPERATOR(hilti, interval, MultipleUnsignedInteger)
HILTI_NODE_OPERATOR(hilti, interval, MultipleReal)
HILTI_NODE_OPERATOR(hilti, interval, CtorSignedIntegerNs)
HILTI_NODE_OPERATOR(hilti, interval, CtorSignedIntegerSecs)
HILTI_NODE_OPERATOR(hilti, interval, CtorUnsignedIntegerNs)
HILTI_NODE_OPERATOR(hilti, interval, CtorUnsignedIntegerSecs)
HILTI_NODE_OPERATOR(hilti, interval, CtorRealSecs)
HILTI_NODE_OPERATOR(hilti, interval, Seconds)
HILTI_NODE_OPERATOR(hilti, interval, Nanoseconds)

} // namespace hilti::operator_
