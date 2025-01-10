// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(signed_integer, DecrPostfix)
HILTI_NODE_OPERATOR(signed_integer, DecrPrefix)
HILTI_NODE_OPERATOR(signed_integer, IncrPostfix)
HILTI_NODE_OPERATOR(signed_integer, IncrPrefix)
HILTI_NODE_OPERATOR(signed_integer, SignNeg)
HILTI_NODE_OPERATOR(signed_integer, Difference)
HILTI_NODE_OPERATOR(signed_integer, DifferenceAssign)
HILTI_NODE_OPERATOR(signed_integer, Division)
HILTI_NODE_OPERATOR(signed_integer, DivisionAssign)
HILTI_NODE_OPERATOR(signed_integer, Equal)
HILTI_NODE_OPERATOR(signed_integer, Greater)
HILTI_NODE_OPERATOR(signed_integer, GreaterEqual)
HILTI_NODE_OPERATOR(signed_integer, Lower)
HILTI_NODE_OPERATOR(signed_integer, LowerEqual)
HILTI_NODE_OPERATOR(signed_integer, Modulo)
HILTI_NODE_OPERATOR(signed_integer, Multiple)
HILTI_NODE_OPERATOR(signed_integer, MultipleAssign)
HILTI_NODE_OPERATOR(signed_integer, Power)
HILTI_NODE_OPERATOR(signed_integer, Sum)
HILTI_NODE_OPERATOR(signed_integer, SumAssign)
HILTI_NODE_OPERATOR(signed_integer, Unequal)
HILTI_NODE_OPERATOR(signed_integer, CastToSigned)
HILTI_NODE_OPERATOR(signed_integer, CastToUnsigned)
HILTI_NODE_OPERATOR(signed_integer, CastToReal)
HILTI_NODE_OPERATOR(signed_integer, CastToEnum)
HILTI_NODE_OPERATOR(signed_integer, CastToInterval)
HILTI_NODE_OPERATOR(signed_integer, CastToBool)
HILTI_NODE_OPERATOR(signed_integer, CtorSigned8)
HILTI_NODE_OPERATOR(signed_integer, CtorSigned16)
HILTI_NODE_OPERATOR(signed_integer, CtorSigned32)
HILTI_NODE_OPERATOR(signed_integer, CtorSigned64)
HILTI_NODE_OPERATOR(signed_integer, CtorUnsigned8)
HILTI_NODE_OPERATOR(signed_integer, CtorUnsigned16)
HILTI_NODE_OPERATOR(signed_integer, CtorUnsigned32)
HILTI_NODE_OPERATOR(signed_integer, CtorUnsigned64)

HILTI_NODE_OPERATOR(unsigned_integer, DecrPostfix)
HILTI_NODE_OPERATOR(unsigned_integer, DecrPrefix)
HILTI_NODE_OPERATOR(unsigned_integer, IncrPostfix)
HILTI_NODE_OPERATOR(unsigned_integer, IncrPrefix)
HILTI_NODE_OPERATOR(unsigned_integer, SignNeg)
HILTI_NODE_OPERATOR(unsigned_integer, Difference)
HILTI_NODE_OPERATOR(unsigned_integer, DifferenceAssign)
HILTI_NODE_OPERATOR(unsigned_integer, Division)
HILTI_NODE_OPERATOR(unsigned_integer, DivisionAssign)
HILTI_NODE_OPERATOR(unsigned_integer, Equal)
HILTI_NODE_OPERATOR(unsigned_integer, Greater)
HILTI_NODE_OPERATOR(unsigned_integer, GreaterEqual)
HILTI_NODE_OPERATOR(unsigned_integer, Lower)
HILTI_NODE_OPERATOR(unsigned_integer, LowerEqual)
HILTI_NODE_OPERATOR(unsigned_integer, Modulo)
HILTI_NODE_OPERATOR(unsigned_integer, Multiple)
HILTI_NODE_OPERATOR(unsigned_integer, MultipleAssign)
HILTI_NODE_OPERATOR(unsigned_integer, Power)
HILTI_NODE_OPERATOR(unsigned_integer, Sum)
HILTI_NODE_OPERATOR(unsigned_integer, SumAssign)
HILTI_NODE_OPERATOR(unsigned_integer, Unequal)
HILTI_NODE_OPERATOR(unsigned_integer, Negate)
HILTI_NODE_OPERATOR(unsigned_integer, BitAnd)
HILTI_NODE_OPERATOR(unsigned_integer, BitOr)
HILTI_NODE_OPERATOR(unsigned_integer, BitXor)
HILTI_NODE_OPERATOR(unsigned_integer, ShiftLeft)
HILTI_NODE_OPERATOR(unsigned_integer, ShiftRight)
HILTI_NODE_OPERATOR(unsigned_integer, CastToUnsigned)
HILTI_NODE_OPERATOR(unsigned_integer, CastToSigned)
HILTI_NODE_OPERATOR(unsigned_integer, CastToReal)
HILTI_NODE_OPERATOR(unsigned_integer, CastToEnum)
HILTI_NODE_OPERATOR(unsigned_integer, CastToInterval)
HILTI_NODE_OPERATOR(unsigned_integer, CastToTime)
HILTI_NODE_OPERATOR(unsigned_integer, CastToBool)
HILTI_NODE_OPERATOR(unsigned_integer, CtorSigned8)
HILTI_NODE_OPERATOR(unsigned_integer, CtorSigned16)
HILTI_NODE_OPERATOR(unsigned_integer, CtorSigned32)
HILTI_NODE_OPERATOR(unsigned_integer, CtorSigned64)
HILTI_NODE_OPERATOR(unsigned_integer, CtorUnsigned8)
HILTI_NODE_OPERATOR(unsigned_integer, CtorUnsigned16)
HILTI_NODE_OPERATOR(unsigned_integer, CtorUnsigned32)
HILTI_NODE_OPERATOR(unsigned_integer, CtorUnsigned64)

} // namespace hilti::operator_
