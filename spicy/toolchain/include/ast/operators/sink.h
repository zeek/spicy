// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace spicy::operator_ {

HILTI_NODE_OPERATOR(spicy, sink, SizeValue)
HILTI_NODE_OPERATOR(spicy, sink, SizeReference)
HILTI_NODE_OPERATOR(spicy, sink, Close)
HILTI_NODE_OPERATOR(spicy, sink, Connect)
HILTI_NODE_OPERATOR(spicy, sink, ConnectMIMETypeString)
HILTI_NODE_OPERATOR(spicy, sink, ConnectMIMETypeBytes)
HILTI_NODE_OPERATOR(spicy, sink, ConnectFilter)
HILTI_NODE_OPERATOR(spicy, sink, Gap)
HILTI_NODE_OPERATOR(spicy, sink, SequenceNumber)
HILTI_NODE_OPERATOR(spicy, sink, SetAutoTrim)
HILTI_NODE_OPERATOR(spicy, sink, SetInitialSequenceNumber)
HILTI_NODE_OPERATOR(spicy, sink, SetPolicy)
HILTI_NODE_OPERATOR(spicy, sink, Skip)
HILTI_NODE_OPERATOR(spicy, sink, Trim)
HILTI_NODE_OPERATOR(spicy, sink, Write)

} // namespace spicy::operator_
