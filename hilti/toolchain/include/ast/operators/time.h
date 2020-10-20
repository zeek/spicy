// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/interval.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/time.h>

namespace hilti {
namespace operator_ {

STANDARD_OPERATOR_2(time, Equal, type::Bool(), type::Time(), type::Time(), "Compares two time values.")
STANDARD_OPERATOR_2(time, Unequal, type::Bool(), type::Time(), type::Time(), "Compares two time values.")
STANDARD_OPERATOR_2x(time, SumInterval, Sum, type::Time(), type::Time(), type::Interval(),
                     "Adds the interval to the time.");
STANDARD_OPERATOR_2x(time, DifferenceTime, Difference, type::Interval(), type::Time(), type::Time(),
                     "Returns the difference of the times.");
STANDARD_OPERATOR_2x(time, DifferenceInterval, Difference, type::Time(), type::Time(), type::Interval(),
                     "Subtracts the interval from the time.");
STANDARD_OPERATOR_2(time, Greater, type::Bool(), type::Time(), type::Time(), "Compares the times.");
STANDARD_OPERATOR_2(time, GreaterEqual, type::Bool(), type::Time(), type::Time(), "Compares the times.");
STANDARD_OPERATOR_2(time, Lower, type::Bool(), type::Time(), type::Time(), "Compares the times.");
STANDARD_OPERATOR_2(time, LowerEqual, type::Bool(), type::Time(), type::Time(), "Compares the times.");

BEGIN_METHOD(time, Seconds)
    auto signature() const {
        return Signature{.self = type::Time(), .result = type::Real(), .id = "seconds", .args = {}, .doc = R"(
Returns the time as a real value representing seconds since the UNIX epoch.
)"};
    }
END_METHOD

BEGIN_METHOD(time, Nanoseconds)
    auto signature() const {
        return Signature{.self = type::Time(), .result = type::UnsignedInteger(64), .id = "nanoseconds", .args = {}, .doc = R"(
Returns the time as an integer value representing nanoseconds since the UNIX epoch.
)"};
    }
END_METHOD

} // namespace operator_
} // namespace hilti
