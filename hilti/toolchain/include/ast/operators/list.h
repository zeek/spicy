// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(list::iterator, Deref)
HILTI_NODE_OPERATOR(list::iterator, IncrPostfix)
HILTI_NODE_OPERATOR(list::iterator, IncrPrefix)
HILTI_NODE_OPERATOR(list::iterator, Equal)
HILTI_NODE_OPERATOR(list::iterator, Unequal)
HILTI_NODE_OPERATOR(list, Size)
HILTI_NODE_OPERATOR(list, Equal)
HILTI_NODE_OPERATOR(list, Unequal)

} // namespace hilti::operator_
