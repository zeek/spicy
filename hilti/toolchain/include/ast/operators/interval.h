// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/builder/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/interval.h>
#include <hilti/ast/types/real.h>

namespace hilti::operator_ {

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

STANDARD_KEYWORD_CTOR(interval, CtorSignedIntegerNs, "interval_ns", type::Interval(),
                      type::SignedInteger(type::Wildcard()),
                      "Creates an interval interpreting the argument as number of nanoseconds.");
STANDARD_KEYWORD_CTOR(interval, CtorSignedIntegerSecs, "interval", type::Interval(),
                      type::SignedInteger(type::Wildcard()),
                      "Creates an interval interpreting the argument as number of seconds.");
STANDARD_KEYWORD_CTOR(interval, CtorUnsignedIntegerNs, "interval_ns", type::Interval(),
                      type::UnsignedInteger(type::Wildcard()),
                      "Creates an interval interpreting the argument as number of nanoseconds.");
STANDARD_KEYWORD_CTOR(interval, CtorUnsignedIntegerSecs, "interval", type::Interval(),
                      type::UnsignedInteger(type::Wildcard()),
                      "Creates an interval interpreting the argument as number of seconds.");
STANDARD_KEYWORD_CTOR(interval, CtorRealSecs, "interval", type::Interval(), type::Real(),
                      "Creates an interval interpreting the argument as number of seconds.");

BEGIN_METHOD(interval, Seconds)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::Interval(), .result = type::Real(), .id = "seconds", .args = {}, .doc = R"(
Returns the interval as a real value representing seconds.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(interval, Nanoseconds)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Interval(),
                                           .result = type::SignedInteger(64),
                                           .id = "nanoseconds",
                                           .args = {},
                                           .doc = R"(
Returns the interval as an integer value representing nanoseconds.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
