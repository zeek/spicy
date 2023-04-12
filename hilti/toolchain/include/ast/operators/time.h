// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/interval.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/time.h>

namespace hilti::operator_ {

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

STANDARD_KEYWORD_CTOR(time, CtorSignedIntegerNs, "time_ns", type::Time(), type::SignedInteger(type::Wildcard()),
                      "Creates an time interpreting the argument as number of nanoseconds.");
STANDARD_KEYWORD_CTOR(time, CtorSignedIntegerSecs, "time", type::Time(), type::SignedInteger(type::Wildcard()),
                      "Creates an time interpreting the argument as number of seconds.");
STANDARD_KEYWORD_CTOR(time, CtorUnsignedIntegerNs, "time_ns", type::Time(), type::UnsignedInteger(type::Wildcard()),
                      "Creates an time interpreting the argument as number of nanoseconds.");
STANDARD_KEYWORD_CTOR(time, CtorUnsignedIntegerSecs, "time", type::Time(), type::UnsignedInteger(type::Wildcard()),
                      "Creates an time interpreting the argument as number of seconds.");
STANDARD_KEYWORD_CTOR(time, CtorRealSecs, "time", type::Time(), type::Real(),
                      "Creates an time interpreting the argument as number of seconds.");

BEGIN_METHOD(time, Seconds)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::Time(), .result = type::Real(), .id = "seconds", .args = {}, .doc = R"(
Returns the time as a real value representing seconds since the UNIX epoch.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(time, Nanoseconds)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Time(),
                                           .result = type::UnsignedInteger(64),
                                           .id = "nanoseconds",
                                           .args = {},
                                           .doc = R"(
Returns the time as an integer value representing nanoseconds since the UNIX epoch.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
