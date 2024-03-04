// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(network, Equal)
HILTI_NODE_OPERATOR(network, Unequal)
HILTI_NODE_OPERATOR(network, In)
HILTI_NODE_OPERATOR(network, Family)
HILTI_NODE_OPERATOR(network, Prefix)
HILTI_NODE_OPERATOR(network, Length)

} // namespace hilti::operator_
