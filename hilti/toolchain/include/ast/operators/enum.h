// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, enum_, Equal)
HILTI_NODE_OPERATOR(hilti, enum_, Unequal)
HILTI_NODE_OPERATOR(hilti, enum_, CastToSignedInteger)
HILTI_NODE_OPERATOR(hilti, enum_, CastToUnsignedInteger)
HILTI_NODE_OPERATOR(hilti, enum_, CtorSigned)
HILTI_NODE_OPERATOR(hilti, enum_, CtorUnsigned)
HILTI_NODE_OPERATOR(hilti, enum_, HasLabel)

} // namespace hilti::operator_
