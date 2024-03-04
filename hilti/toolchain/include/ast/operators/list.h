// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, list::iterator, Deref)
HILTI_NODE_OPERATOR(hilti, list::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(hilti, list::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(hilti, list::iterator, Equal)
HILTI_NODE_OPERATOR(hilti, list::iterator, Unequal)
HILTI_NODE_OPERATOR(hilti, list, Size)
HILTI_NODE_OPERATOR(hilti, list, Equal)
HILTI_NODE_OPERATOR(hilti, list, Unequal)

} // namespace hilti::operator_
