// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(union_, Equal)
HILTI_NODE_OPERATOR(union_, Unequal)
HILTI_NODE_OPERATOR(union_, MemberConst)
HILTI_NODE_OPERATOR(union_, MemberNonConst)
HILTI_NODE_OPERATOR(union_, HasMember)

} // namespace hilti::operator_
