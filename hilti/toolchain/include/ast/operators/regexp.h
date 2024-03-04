// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

HILTI_NODE_OPERATOR(hilti, regexp, Match)
HILTI_NODE_OPERATOR(hilti, regexp, Find)
HILTI_NODE_OPERATOR(hilti, regexp, MatchGroups)
HILTI_NODE_OPERATOR(hilti, regexp, TokenMatcher)

HILTI_NODE_OPERATOR(hilti, regexp_match_state, AdvanceBytes)
HILTI_NODE_OPERATOR(hilti, regexp_match_state, AdvanceView)

} // namespace hilti::operator_
