// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, map::iterator, Deref)
HILTI_NODE_OPERATOR(hilti, map::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(hilti, map::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(hilti, map::iterator, Equal)
HILTI_NODE_OPERATOR(hilti, map::iterator, Unequal)
HILTI_NODE_OPERATOR(hilti, map, Size)
HILTI_NODE_OPERATOR(hilti, map, Equal)
HILTI_NODE_OPERATOR(hilti, map, Unequal)
HILTI_NODE_OPERATOR(hilti, map, In)
HILTI_NODE_OPERATOR(hilti, map, Delete)
HILTI_NODE_OPERATOR(hilti, map, IndexConst)
HILTI_NODE_OPERATOR(hilti, map, IndexNonConst)
HILTI_NODE_OPERATOR(hilti, map, IndexAssign)
HILTI_NODE_OPERATOR(hilti, map, Get)
HILTI_NODE_OPERATOR(hilti, map, Clear)

} // namespace hilti::operator_
