// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

// NOLINTNEXTLINE(modernize-concat-nested-namespaces)
namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, port, Equal)
HILTI_NODE_OPERATOR(hilti, port, Unequal)
HILTI_NODE_OPERATOR(hilti, port, Ctor)
HILTI_NODE_OPERATOR(hilti, port, Protocol)

} // namespace hilti::operator_
