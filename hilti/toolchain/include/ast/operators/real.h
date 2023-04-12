// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>

namespace hilti::operator_ {
STANDARD_OPERATOR_1(real, SignNeg, type::Real(), type::Real(), "Inverts the sign of the real.");
STANDARD_OPERATOR_2(real, Difference, type::Real(), type::Real(), type::Real(),
                    "Returns the difference between the two values.");
STANDARD_OPERATOR_2(real, DifferenceAssign, type::Real(), type::Real(), type::Real(),
                    "Subtracts the second value from the first, assigning the new value.");
STANDARD_OPERATOR_2(real, Division, type::Real(), type::Real(), type::Real(), "Divides the first value by the second.");
STANDARD_OPERATOR_2(real, DivisionAssign, type::Real(), type::Real(), type::Real(),
                    "Divides the first value by the second, assigning the new value.");
STANDARD_OPERATOR_2(real, Equal, type::Bool(), type::Real(), type::Real(), "Compares the two reals.");
STANDARD_OPERATOR_2(real, Greater, type::Bool(), type::Real(), type::Real(), "Compares the two reals.");
STANDARD_OPERATOR_2(real, GreaterEqual, type::Bool(), type::Real(), type::Real(), "Compares the two reals.");
STANDARD_OPERATOR_2(real, Lower, type::Bool(), type::Real(), type::Real(), "Compares the two reals.");
STANDARD_OPERATOR_2(real, LowerEqual, type::Bool(), type::Real(), type::Real(), "Compares the two reals.");
STANDARD_OPERATOR_2(real, Modulo, type::Real(), type::Real(), type::Real(),
                    "Computes the modulus of the first real divided by the second.");
STANDARD_OPERATOR_2(real, Multiple, type::Real(), type::Real(), type::Real(),
                    "Multiplies the first real by the second.");
STANDARD_OPERATOR_2(real, MultipleAssign, type::Real(), type::Real(), type::Real(),
                    "Multiplies the first value by the second, assigning the new value.");
STANDARD_OPERATOR_2(real, Power, type::Real(), type::Real(), type::Real(),
                    "Computes the first real raised to the power of the second.");
STANDARD_OPERATOR_2(real, Sum, type::Real(), type::Real(), type::Real(), "Returns the sum of the reals.");
STANDARD_OPERATOR_2(real, SumAssign, type::Real(), type::Real(), type::Real(),
                    "Adds the first real to the second, assigning the new value.");
STANDARD_OPERATOR_2(real, Unequal, type::Bool(), type::Real(), type::Real(), "Compares the two reals.");

STANDARD_OPERATOR_2x(real, CastToUnsignedInteger, Cast, operator_::typedType(1, "uint<*>"), type::Real(),
                     type::Type_(type::UnsignedInteger(type::Wildcard())),
                     "Converts the value to an unsigned integer type, accepting any loss of information.");
STANDARD_OPERATOR_2x(real, CastToSignedInteger, Cast, operator_::typedType(1, "int<*>"), type::Real(),
                     type::Type_(type::SignedInteger(type::Wildcard())),
                     "Converts the value to a signed integer type, accepting any loss of information.");
STANDARD_OPERATOR_2x(real, CastToTime, Cast, type::Time(), type::Real(), type::Type_(type::Time()),
                     "Interprets the value as number of seconds since the UNIX epoch.");
STANDARD_OPERATOR_2x(real, CastToInterval, Cast, type::Interval(), type::Real(), type::Type_(type::Interval()),
                     "Interprets the value as number of seconds.");

} // namespace hilti::operator_
