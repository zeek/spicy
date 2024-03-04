// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(bytes::iterator, Deref)
HILTI_NODE_OPERATOR(bytes::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(bytes::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(bytes::iterator, Equal)
HILTI_NODE_OPERATOR(bytes::iterator, Unequal)
HILTI_NODE_OPERATOR(bytes::iterator, Lower)
HILTI_NODE_OPERATOR(bytes::iterator, LowerEqual)
HILTI_NODE_OPERATOR(bytes::iterator, Greater)
HILTI_NODE_OPERATOR(bytes::iterator, GreaterEqual)
HILTI_NODE_OPERATOR(bytes::iterator, Difference)
HILTI_NODE_OPERATOR(bytes::iterator, Sum)
HILTI_NODE_OPERATOR(bytes::iterator, SumAssign)
HILTI_NODE_OPERATOR(bytes, Size)
HILTI_NODE_OPERATOR(bytes, Equal)
HILTI_NODE_OPERATOR(bytes, Unequal)
HILTI_NODE_OPERATOR(bytes, Greater)
HILTI_NODE_OPERATOR(bytes, GreaterEqual)
HILTI_NODE_OPERATOR(bytes, In)
HILTI_NODE_OPERATOR(bytes, Lower)
HILTI_NODE_OPERATOR(bytes, LowerEqual)
HILTI_NODE_OPERATOR(bytes, Sum)
HILTI_NODE_OPERATOR(bytes, SumAssignBytes)
HILTI_NODE_OPERATOR(bytes, SumAssignStreamView)
HILTI_NODE_OPERATOR(bytes, SumAssignUInt8)
HILTI_NODE_OPERATOR(bytes, Find)
HILTI_NODE_OPERATOR(bytes, LowerCase)
HILTI_NODE_OPERATOR(bytes, UpperCase)
HILTI_NODE_OPERATOR(bytes, At)
HILTI_NODE_OPERATOR(bytes, Split)
HILTI_NODE_OPERATOR(bytes, Split1)
HILTI_NODE_OPERATOR(bytes, StartsWith)
HILTI_NODE_OPERATOR(bytes, Strip)
HILTI_NODE_OPERATOR(bytes, SubIterators)
HILTI_NODE_OPERATOR(bytes, SubIterator)
HILTI_NODE_OPERATOR(bytes, SubOffsets)
HILTI_NODE_OPERATOR(bytes, Join)
HILTI_NODE_OPERATOR(bytes, ToIntAscii)
HILTI_NODE_OPERATOR(bytes, ToUIntAscii)
HILTI_NODE_OPERATOR(bytes, ToIntBinary)
HILTI_NODE_OPERATOR(bytes, ToUIntBinary)
HILTI_NODE_OPERATOR(bytes, ToTimeAscii)
HILTI_NODE_OPERATOR(bytes, ToTimeBinary)
HILTI_NODE_OPERATOR(bytes, Decode)
HILTI_NODE_OPERATOR(bytes, Match)

} // namespace hilti::operator_
