// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, stream::iterator, Deref)
HILTI_NODE_OPERATOR(hilti, stream::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(hilti, stream::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(hilti, stream::iterator, Equal)
HILTI_NODE_OPERATOR(hilti, stream::iterator, Unequal)
HILTI_NODE_OPERATOR(hilti, stream::iterator, Lower)
HILTI_NODE_OPERATOR(hilti, stream::iterator, LowerEqual)
HILTI_NODE_OPERATOR(hilti, stream::iterator, Greater)
HILTI_NODE_OPERATOR(hilti, stream::iterator, GreaterEqual)
HILTI_NODE_OPERATOR(hilti, stream::iterator, Difference)
HILTI_NODE_OPERATOR(hilti, stream::iterator, Sum)
HILTI_NODE_OPERATOR(hilti, stream::iterator, SumAssign)
HILTI_NODE_OPERATOR(hilti, stream::iterator, Offset)
HILTI_NODE_OPERATOR(hilti, stream::iterator, IsFrozen)
HILTI_NODE_OPERATOR(hilti, stream::view, Size)
HILTI_NODE_OPERATOR(hilti, stream::view, InBytes)
HILTI_NODE_OPERATOR(hilti, stream::view, InView)
HILTI_NODE_OPERATOR(hilti, stream::view, EqualView)
HILTI_NODE_OPERATOR(hilti, stream::view, EqualBytes)
HILTI_NODE_OPERATOR(hilti, stream::view, UnequalView)
HILTI_NODE_OPERATOR(hilti, stream::view, UnequalBytes)
HILTI_NODE_OPERATOR(hilti, stream::view, Offset)
HILTI_NODE_OPERATOR(hilti, stream::view, AdvanceBy)
HILTI_NODE_OPERATOR(hilti, stream::view, AdvanceToNextData)
HILTI_NODE_OPERATOR(hilti, stream::view, Limit)
HILTI_NODE_OPERATOR(hilti, stream::view, AdvanceTo)
HILTI_NODE_OPERATOR(hilti, stream::view, Find)
HILTI_NODE_OPERATOR(hilti, stream::view, At)
HILTI_NODE_OPERATOR(hilti, stream::view, StartsWith)
HILTI_NODE_OPERATOR(hilti, stream::view, SubIterators)
HILTI_NODE_OPERATOR(hilti, stream::view, SubIterator)
HILTI_NODE_OPERATOR(hilti, stream::view, SubOffsets)
HILTI_NODE_OPERATOR(hilti, stream, Ctor)
HILTI_NODE_OPERATOR(hilti, stream, Size)
HILTI_NODE_OPERATOR(hilti, stream, Unequal)
HILTI_NODE_OPERATOR(hilti, stream, SumAssignView)
HILTI_NODE_OPERATOR(hilti, stream, SumAssignBytes)
HILTI_NODE_OPERATOR(hilti, stream, Freeze)
HILTI_NODE_OPERATOR(hilti, stream, Unfreeze)
HILTI_NODE_OPERATOR(hilti, stream, IsFrozen)
HILTI_NODE_OPERATOR(hilti, stream, At)
HILTI_NODE_OPERATOR(hilti, stream, Trim)

} // namespace hilti::operator_
