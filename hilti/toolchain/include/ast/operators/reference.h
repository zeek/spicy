// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(strong_reference, Deref)
HILTI_NODE_OPERATOR(strong_reference, Equal)
HILTI_NODE_OPERATOR(strong_reference, Unequal)
HILTI_NODE_OPERATOR(weak_reference, Deref)
HILTI_NODE_OPERATOR(weak_reference, Equal)
HILTI_NODE_OPERATOR(weak_reference, Unequal)
HILTI_NODE_OPERATOR(value_reference, Deref)
HILTI_NODE_OPERATOR(value_reference, Equal)
HILTI_NODE_OPERATOR(value_reference, Unequal)

} // namespace hilti::operator_
