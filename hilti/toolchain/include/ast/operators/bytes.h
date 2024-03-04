// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, bytes::iterator, Deref)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, Equal)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, Unequal)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, Lower)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, LowerEqual)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, Greater)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, GreaterEqual)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, Difference)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, Sum)
HILTI_NODE_OPERATOR(hilti, bytes::iterator, SumAssign)
HILTI_NODE_OPERATOR(hilti, bytes, Size)
HILTI_NODE_OPERATOR(hilti, bytes, Equal)
HILTI_NODE_OPERATOR(hilti, bytes, Unequal)
HILTI_NODE_OPERATOR(hilti, bytes, Greater)
HILTI_NODE_OPERATOR(hilti, bytes, GreaterEqual)
HILTI_NODE_OPERATOR(hilti, bytes, In)
HILTI_NODE_OPERATOR(hilti, bytes, Lower)
HILTI_NODE_OPERATOR(hilti, bytes, LowerEqual)
HILTI_NODE_OPERATOR(hilti, bytes, Sum)
HILTI_NODE_OPERATOR(hilti, bytes, SumAssignBytes)
HILTI_NODE_OPERATOR(hilti, bytes, SumAssignStreamView)
HILTI_NODE_OPERATOR(hilti, bytes, SumAssignUInt8)
HILTI_NODE_OPERATOR(hilti, bytes, Find)
HILTI_NODE_OPERATOR(hilti, bytes, LowerCase)
HILTI_NODE_OPERATOR(hilti, bytes, UpperCase)
HILTI_NODE_OPERATOR(hilti, bytes, At)
HILTI_NODE_OPERATOR(hilti, bytes, Split)
HILTI_NODE_OPERATOR(hilti, bytes, Split1)
HILTI_NODE_OPERATOR(hilti, bytes, StartsWith)
HILTI_NODE_OPERATOR(hilti, bytes, Strip)
HILTI_NODE_OPERATOR(hilti, bytes, SubIterators)
HILTI_NODE_OPERATOR(hilti, bytes, SubIterator)
HILTI_NODE_OPERATOR(hilti, bytes, SubOffsets)
HILTI_NODE_OPERATOR(hilti, bytes, Join)
HILTI_NODE_OPERATOR(hilti, bytes, ToIntAscii)
HILTI_NODE_OPERATOR(hilti, bytes, ToUIntAscii)
HILTI_NODE_OPERATOR(hilti, bytes, ToIntBinary)
HILTI_NODE_OPERATOR(hilti, bytes, ToUIntBinary)
HILTI_NODE_OPERATOR(hilti, bytes, ToTimeAscii)
HILTI_NODE_OPERATOR(hilti, bytes, ToTimeBinary)
HILTI_NODE_OPERATOR(hilti, bytes, Decode)
HILTI_NODE_OPERATOR(hilti, bytes, Match)

} // namespace hilti::operator_
