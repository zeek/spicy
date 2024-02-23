// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, address, Equal)
HILTI_NODE_OPERATOR(hilti, address, Unequal)
HILTI_NODE_OPERATOR(hilti, address, Family)

} // namespace hilti::operator_
