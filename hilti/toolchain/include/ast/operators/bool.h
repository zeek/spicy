// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/string.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_2(bool_, Equal, type::Bool(), type::Bool(), type::Bool(), "Compares two boolean values.")
STANDARD_OPERATOR_2(bool_, Unequal, type::Bool(), type::Bool(), type::Bool(), "Compares two boolean values.")
STANDARD_OPERATOR_2(bool_, BitAnd, type::Bool(), type::Bool(), type::Bool(),
                    "Computes the bit-wise 'and' of the two boolean values.");
STANDARD_OPERATOR_2(bool_, BitOr, type::Bool(), type::Bool(), type::Bool(),
                    "Computes the bit-wise 'or' of the two boolean values.");
STANDARD_OPERATOR_2(bool_, BitXor, type::Bool(), type::Bool(), type::Bool(),
                    "Computes the bit-wise 'xor' of the two boolean values.");

} // namespace hilti::operator_
