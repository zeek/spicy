// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

#include <spicy/ast/forward.h>

namespace spicy::operator_ {

SPICY_NODE_OPERATOR(sink, SizeValue)
SPICY_NODE_OPERATOR(sink, SizeReference)
SPICY_NODE_OPERATOR(sink, Close)
SPICY_NODE_OPERATOR(sink, Connect)
SPICY_NODE_OPERATOR(sink, ConnectMIMETypeString)
SPICY_NODE_OPERATOR(sink, ConnectMIMETypeBytes)
SPICY_NODE_OPERATOR(sink, ConnectFilter)
SPICY_NODE_OPERATOR(sink, Gap)
SPICY_NODE_OPERATOR(sink, SequenceNumber)
SPICY_NODE_OPERATOR(sink, SetAutoTrim)
SPICY_NODE_OPERATOR(sink, SetInitialSequenceNumber)
SPICY_NODE_OPERATOR(sink, SetPolicy)
SPICY_NODE_OPERATOR(sink, Skip)
SPICY_NODE_OPERATOR(sink, Trim)
SPICY_NODE_OPERATOR(sink, Write)

} // namespace spicy::operator_
