// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(stream::iterator, Deref)
HILTI_NODE_OPERATOR(stream::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(stream::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(stream::iterator, Equal)
HILTI_NODE_OPERATOR(stream::iterator, Unequal)
HILTI_NODE_OPERATOR(stream::iterator, Lower)
HILTI_NODE_OPERATOR(stream::iterator, LowerEqual)
HILTI_NODE_OPERATOR(stream::iterator, Greater)
HILTI_NODE_OPERATOR(stream::iterator, GreaterEqual)
HILTI_NODE_OPERATOR(stream::iterator, Difference)
HILTI_NODE_OPERATOR(stream::iterator, Sum)
HILTI_NODE_OPERATOR(stream::iterator, SumAssign)
HILTI_NODE_OPERATOR(stream::iterator, Offset)
HILTI_NODE_OPERATOR(stream::iterator, IsFrozen)
HILTI_NODE_OPERATOR(stream::view, Size)
HILTI_NODE_OPERATOR(stream::view, InBytes)
HILTI_NODE_OPERATOR(stream::view, InView)
HILTI_NODE_OPERATOR(stream::view, EqualView)
HILTI_NODE_OPERATOR(stream::view, EqualBytes)
HILTI_NODE_OPERATOR(stream::view, UnequalView)
HILTI_NODE_OPERATOR(stream::view, UnequalBytes)
HILTI_NODE_OPERATOR(stream::view, Offset)
HILTI_NODE_OPERATOR(stream::view, AdvanceBy)
HILTI_NODE_OPERATOR(stream::view, AdvanceToNextData)
HILTI_NODE_OPERATOR(stream::view, Limit)
HILTI_NODE_OPERATOR(stream::view, AdvanceTo)
HILTI_NODE_OPERATOR(stream::view, Find)
HILTI_NODE_OPERATOR(stream::view, At)
HILTI_NODE_OPERATOR(stream::view, StartsWith)
HILTI_NODE_OPERATOR(stream::view, SubIterators)
HILTI_NODE_OPERATOR(stream::view, SubIterator)
HILTI_NODE_OPERATOR(stream::view, SubOffsets)
HILTI_NODE_OPERATOR(stream, Ctor)
HILTI_NODE_OPERATOR(stream, Size)
HILTI_NODE_OPERATOR(stream, Unequal)
HILTI_NODE_OPERATOR(stream, SumAssignView)
HILTI_NODE_OPERATOR(stream, SumAssignBytes)
HILTI_NODE_OPERATOR(stream, Freeze)
HILTI_NODE_OPERATOR(stream, Unfreeze)
HILTI_NODE_OPERATOR(stream, IsFrozen)
HILTI_NODE_OPERATOR(stream, At)
HILTI_NODE_OPERATOR(stream, Trim)

} // namespace hilti::operator_
