// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(map::iterator, Deref)
HILTI_NODE_OPERATOR(map::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(map::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(map::iterator, Equal)
HILTI_NODE_OPERATOR(map::iterator, Unequal)
HILTI_NODE_OPERATOR(map, Size)
HILTI_NODE_OPERATOR(map, Equal)
HILTI_NODE_OPERATOR(map, Unequal)
HILTI_NODE_OPERATOR(map, In)
HILTI_NODE_OPERATOR(map, Delete)
HILTI_NODE_OPERATOR(map, IndexConst)
HILTI_NODE_OPERATOR(map, IndexNonConst)
HILTI_NODE_OPERATOR(map, IndexAssign)
HILTI_NODE_OPERATOR(map, Get)
HILTI_NODE_OPERATOR(map, Clear)

} // namespace hilti::operator_
