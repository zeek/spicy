// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/result.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_1(optional, Deref, operator_::dereferencedType(0), type::constant(type::Optional(type::Wildcard())),
                    "Returns the element stored, or throws an exception if none.");

} // namespace hilti::operator_
