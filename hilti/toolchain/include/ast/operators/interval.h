// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/builder/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/interval.h>
#include <hilti/ast/types/real.h>

namespace hilti {
namespace operator_ {

STANDARD_OPERATOR_2(interval, Equal, type::Bool(), type::Interval(), type::Interval(), "Compares two interval values.")
STANDARD_OPERATOR_2(interval, Unequal, type::Bool(), type::Interval(), type::Interval(),
                    "Compares two interval values.")
STANDARD_OPERATOR_2(interval, Sum, type::Interval(), type::Interval(), type::Interval(),
                    "Returns the sum of the intervals.");
STANDARD_OPERATOR_2(interval, Difference, type::Interval(), type::Interval(), type::Interval(),
                    "Returns the difference of the intervals.");
STANDARD_OPERATOR_2(interval, Greater, type::Bool(), type::Interval(), type::Interval(), "Compares the intervals.");
STANDARD_OPERATOR_2(interval, GreaterEqual, type::Bool(), type::Interval(), type::Interval(),
                    "Compares the intervals.");
STANDARD_OPERATOR_2(interval, Lower, type::Bool(), type::Interval(), type::Interval(), "Compares the intervals.");
STANDARD_OPERATOR_2(interval, LowerEqual, type::Bool(), type::Interval(), type::Interval(), "Compares the intervals.");
STANDARD_OPERATOR_2x(interval, MultipleUnsignedInteger, Multiple, type::Interval(), type::Interval(),
                     type::UnsignedInteger(64), "Multiples the interval with the given factor.");
STANDARD_OPERATOR_2x(interval, MultipleReal, Multiple, type::Interval(), type::Interval(), type::Real(),
                     "Multiplies the interval with the given factor.");

BEGIN_METHOD(interval, Seconds)
    auto signature() const {
        return Signature{.self = type::Interval(), .result = type::Real(), .id = "seconds", .args = {}, .doc = R"(
Returns the interval as a real value representing seconds.
)"};
    }
END_METHOD

BEGIN_METHOD(interval, Nanoseconds)
    auto signature() const {
        return Signature{.self = type::Interval(), .result = type::SignedInteger(64), .id = "nanoseconds", .args = {}, .doc = R"(
Returns the interval as an integer value representing nanoseconds.
)"};
    }
END_METHOD

} // namespace operator_
} // namespace hilti
