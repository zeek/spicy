// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, set::iterator, Deref)
HILTI_NODE_OPERATOR(hilti, set::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(hilti, set::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(hilti, set::iterator, Equal)
HILTI_NODE_OPERATOR(hilti, set::iterator, Unequal)
HILTI_NODE_OPERATOR(hilti, set, Size)
HILTI_NODE_OPERATOR(hilti, set, Equal)
HILTI_NODE_OPERATOR(hilti, set, Unequal)
HILTI_NODE_OPERATOR(hilti, set, In)
HILTI_NODE_OPERATOR(hilti, set, Add)
HILTI_NODE_OPERATOR(hilti, set, Delete)
HILTI_NODE_OPERATOR(hilti, set, Clear)

} // namespace hilti::operator_
