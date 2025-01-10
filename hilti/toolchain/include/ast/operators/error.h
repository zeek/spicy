// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(error, Ctor)
HILTI_NODE_OPERATOR(error, Equal)
HILTI_NODE_OPERATOR(error, Unequal)
HILTI_NODE_OPERATOR(error, Description)

} // namespace hilti::operator_
