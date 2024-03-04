// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(interval, Equal)
HILTI_NODE_OPERATOR(interval, Unequal)
HILTI_NODE_OPERATOR(interval, Sum)
HILTI_NODE_OPERATOR(interval, Difference)
HILTI_NODE_OPERATOR(interval, Greater)
HILTI_NODE_OPERATOR(interval, GreaterEqual)
HILTI_NODE_OPERATOR(interval, Lower)
HILTI_NODE_OPERATOR(interval, LowerEqual)
HILTI_NODE_OPERATOR(interval, MultipleUnsignedInteger)
HILTI_NODE_OPERATOR(interval, MultipleReal)
HILTI_NODE_OPERATOR(interval, CtorSignedIntegerNs)
HILTI_NODE_OPERATOR(interval, CtorSignedIntegerSecs)
HILTI_NODE_OPERATOR(interval, CtorUnsignedIntegerNs)
HILTI_NODE_OPERATOR(interval, CtorUnsignedIntegerSecs)
HILTI_NODE_OPERATOR(interval, CtorRealSecs)
HILTI_NODE_OPERATOR(interval, Seconds)
HILTI_NODE_OPERATOR(interval, Nanoseconds)

} // namespace hilti::operator_
