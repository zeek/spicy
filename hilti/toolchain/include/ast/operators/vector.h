// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(vector::iterator, Deref)
HILTI_NODE_OPERATOR(vector::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(vector::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(vector::iterator, Equal)
HILTI_NODE_OPERATOR(vector::iterator, Unequal)
HILTI_NODE_OPERATOR(vector, Size)
HILTI_NODE_OPERATOR(vector, Equal)
HILTI_NODE_OPERATOR(vector, Unequal)
HILTI_NODE_OPERATOR(vector, IndexConst)
HILTI_NODE_OPERATOR(vector, IndexNonConst)
HILTI_NODE_OPERATOR(vector, Sum)
HILTI_NODE_OPERATOR(vector, SumAssign)
HILTI_NODE_OPERATOR(vector, Assign)
HILTI_NODE_OPERATOR(vector, PushBack)
HILTI_NODE_OPERATOR(vector, PopBack)
HILTI_NODE_OPERATOR(vector, Front)
HILTI_NODE_OPERATOR(vector, Back)
HILTI_NODE_OPERATOR(vector, Reserve)
HILTI_NODE_OPERATOR(vector, Resize)
HILTI_NODE_OPERATOR(vector, At)
HILTI_NODE_OPERATOR(vector, SubRange)
HILTI_NODE_OPERATOR(vector, SubEnd)

} // namespace hilti::operator_
