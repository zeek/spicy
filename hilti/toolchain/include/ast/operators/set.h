// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(set::iterator, Deref)
HILTI_NODE_OPERATOR(set::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(set::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(set::iterator, Equal)
HILTI_NODE_OPERATOR(set::iterator, Unequal)
HILTI_NODE_OPERATOR(set, Size)
HILTI_NODE_OPERATOR(set, Equal)
HILTI_NODE_OPERATOR(set, Unequal)
HILTI_NODE_OPERATOR(set, In)
HILTI_NODE_OPERATOR(set, Add)
HILTI_NODE_OPERATOR(set, Delete)
HILTI_NODE_OPERATOR(set, Clear)

} // namespace hilti::operator_
