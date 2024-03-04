// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, union_, Equal)
HILTI_NODE_OPERATOR(hilti, union_, Unequal)
HILTI_NODE_OPERATOR(hilti, union_, MemberConst)
HILTI_NODE_OPERATOR(hilti, union_, MemberNonConst)
HILTI_NODE_OPERATOR(hilti, union_, HasMember)

} // namespace hilti::operator_
