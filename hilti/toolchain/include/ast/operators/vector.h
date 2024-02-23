// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, vector::iterator, Deref)
HILTI_NODE_OPERATOR(hilti, vector::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(hilti, vector::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(hilti, vector::iterator, Equal)
HILTI_NODE_OPERATOR(hilti, vector::iterator, Unequal)
HILTI_NODE_OPERATOR(hilti, vector, Size)
HILTI_NODE_OPERATOR(hilti, vector, Equal)
HILTI_NODE_OPERATOR(hilti, vector, Unequal)
HILTI_NODE_OPERATOR(hilti, vector, IndexConst)
HILTI_NODE_OPERATOR(hilti, vector, IndexNonConst)
HILTI_NODE_OPERATOR(hilti, vector, Sum)
HILTI_NODE_OPERATOR(hilti, vector, SumAssign)
HILTI_NODE_OPERATOR(hilti, vector, Assign)
HILTI_NODE_OPERATOR(hilti, vector, PushBack)
HILTI_NODE_OPERATOR(hilti, vector, PopBack)
HILTI_NODE_OPERATOR(hilti, vector, Front)
HILTI_NODE_OPERATOR(hilti, vector, Back)
HILTI_NODE_OPERATOR(hilti, vector, Reserve)
HILTI_NODE_OPERATOR(hilti, vector, Resize)
HILTI_NODE_OPERATOR(hilti, vector, At)
HILTI_NODE_OPERATOR(hilti, vector, SubRange)
HILTI_NODE_OPERATOR(hilti, vector, SubEnd)

} // namespace hilti::operator_
