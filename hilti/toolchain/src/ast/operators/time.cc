// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/interval.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/time.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace time {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeTime()},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "time",
            .doc = "Compares two time values.",
        };
    }

    HILTI_OPERATOR(hilti, time::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeTime()},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "time",
            .doc = "Compares two time values.",
        };
    }

    HILTI_OPERATOR(hilti, time::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

class SumInterval : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Sum,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeInterval()},
            .result = {Constness::Const, builder->typeTime()},
            .ns = "time",
            .doc = "Adds the interval to the time.",
        };
    }

    HILTI_OPERATOR(hilti, time::SumInterval)
};
HILTI_OPERATOR_IMPLEMENTATION(SumInterval);

class DifferenceTime : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Difference,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeTime()},
            .result = {Constness::Const, builder->typeInterval()},
            .ns = "time",
            .doc = "Returns the difference of the times.",
        };
    }

    HILTI_OPERATOR(hilti, time::DifferenceTime)
};
HILTI_OPERATOR_IMPLEMENTATION(DifferenceTime);

class DifferenceInterval : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Difference,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeInterval()},
            .result = {Constness::Const, builder->typeTime()},
            .ns = "time",
            .doc = "Subtracts the interval from the time.",
        };
    }

    HILTI_OPERATOR(hilti, time::DifferenceInterval)
};
HILTI_OPERATOR_IMPLEMENTATION(DifferenceInterval);

class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Greater,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeTime()},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "time",
            .doc = "Compares the times.",
        };
    }

    HILTI_OPERATOR(hilti, time::Greater)
};
HILTI_OPERATOR_IMPLEMENTATION(Greater);

class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::GreaterEqual,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeTime()},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "time",
            .doc = "Compares the times.",
        };
    }

    HILTI_OPERATOR(hilti, time::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);

class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Lower,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeTime()},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "time",
            .doc = "Compares the times.",
        };
    }

    HILTI_OPERATOR(hilti, time::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);

class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::LowerEqual,
            .op0 = {parameter::Kind::In, builder->typeTime()},
            .op1 = {parameter::Kind::In, builder->typeTime()},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "time",
            .doc = "Compares the times.",
        };
    }

    HILTI_OPERATOR(hilti, time::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);

class CtorSignedIntegerNs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "time_ns",
            .param0 =
                {
                    .type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
                },
            .result = {Constness::Const, builder->typeTime()},
            .ns = "time",
            .doc = "Creates an time interpreting the argument as number of nanoseconds.",
        };
    }

    HILTI_OPERATOR(hilti, time::CtorSignedIntegerNs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSignedIntegerNs);

class CtorSignedIntegerSecs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "time",
            .param0 =
                {
                    .type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
                },
            .result = {Constness::Const, builder->typeTime()},
            .ns = "time",
            .doc = "Creates an time interpreting the argument as number of seconds.",
        };
    }

    HILTI_OPERATOR(hilti, time::CtorSignedIntegerSecs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSignedIntegerSecs);

class CtorUnsignedIntegerNs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "time_ns",
            .param0 =
                {
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
                },
            .result = {Constness::Const, builder->typeTime()},
            .ns = "time",
            .doc = "Creates an time interpreting the argument as number of nanoseconds.",
        };
    }

    HILTI_OPERATOR(hilti, time::CtorUnsignedIntegerNs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsignedIntegerNs);

class CtorUnsignedIntegerSecs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "time",
            .param0 =
                {
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
                },
            .result = {Constness::Const, builder->typeTime()},
            .ns = "time",
            .doc = "Creates an time interpreting the argument as number of seconds.",
        };
    }

    HILTI_OPERATOR(hilti, time::CtorUnsignedIntegerSecs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsignedIntegerSecs);

class CtorRealSecs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "time",
            .param0 =
                {
                    .type = {parameter::Kind::In, builder->typeReal()},
                },
            .result = {Constness::Const, builder->typeTime()},
            .ns = "time",
            .doc = "Creates an time interpreting the argument as number of seconds.",
        };
    }

    HILTI_OPERATOR(hilti, time::CtorRealSecs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorRealSecs);

class Seconds : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeTime()},
            .member = "seconds",
            .result = {Constness::Const, builder->typeReal()},
            .ns = "time",
            .doc = R"(
Returns the time as a real value representing seconds since the UNIX epoch.
)",
        };
    }

    HILTI_OPERATOR(hilti, time::Seconds);
};
HILTI_OPERATOR_IMPLEMENTATION(Seconds);

class Nanoseconds : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeTime()},
            .member = "nanoseconds",
            .result = {Constness::Const, builder->typeUnsignedInteger(64)},
            .ns = "time",
            .doc = R"(
Returns the time as an integer value representing nanoseconds since the UNIX epoch.
)",
        };
    }

    HILTI_OPERATOR(hilti, time::Nanoseconds);
};
HILTI_OPERATOR_IMPLEMENTATION(Nanoseconds);

} // namespace time
} // namespace
