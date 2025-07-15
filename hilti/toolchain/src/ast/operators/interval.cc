// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/interval.h>
#include <hilti/ast/types/real.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace interval {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "interval",
            .doc = "Compares two interval values.",
        };
    }

    HILTI_OPERATOR(hilti, interval::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "interval",
            .doc = "Compares two interval values.",
        };
    }

    HILTI_OPERATOR(hilti, interval::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Sum,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Returns the sum of the intervals.",
        };
    }

    HILTI_OPERATOR(hilti, interval::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum);

class Difference : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Difference,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Returns the difference of the intervals.",
        };
    }

    HILTI_OPERATOR(hilti, interval::Difference)
};
HILTI_OPERATOR_IMPLEMENTATION(Difference);

class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Greater,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "interval",
            .doc = "Compares the intervals.",
        };
    }

    HILTI_OPERATOR(hilti, interval::Greater)
};

HILTI_OPERATOR_IMPLEMENTATION(Greater);
class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::GreaterEqual,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "interval",
            .doc = "Compares the intervals.",
        };
    }

    HILTI_OPERATOR(hilti, interval::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);

class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Lower,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "interval",
            .doc = "Compares the intervals.",
        };
    }

    HILTI_OPERATOR(hilti, interval::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);

class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::LowerEqual,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "interval",
            .doc = "Compares the intervals.",
        };
    }

    HILTI_OPERATOR(hilti, interval::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);

class MultipleUnsignedInteger : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Multiple,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Multiples the interval with the given factor.",
        };
    }

    HILTI_OPERATOR(hilti, interval::MultipleUnsignedInteger)
};
HILTI_OPERATOR_IMPLEMENTATION(MultipleUnsignedInteger);

class MultipleReal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Multiple,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Multiplies the interval with the given factor.",
        };
    }

    HILTI_OPERATOR(hilti, interval::MultipleReal)
};
HILTI_OPERATOR_IMPLEMENTATION(MultipleReal);

class CtorSignedIntegerNs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "interval_ns",
            .param0 =
                {
                    .type = {.kind = parameter::Kind::In, .type = builder->typeSignedInteger(type::Wildcard())},
                },
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Creates an interval interpreting the argument as number of nanoseconds.",
        };
    }

    HILTI_OPERATOR(hilti, interval::CtorSignedIntegerNs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSignedIntegerNs);

class CtorSignedIntegerSecs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "interval",
            .param0 =
                {
                    .type = {.kind = parameter::Kind::In, .type = builder->typeSignedInteger(type::Wildcard())},
                },
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Creates an interval interpreting the argument as number of seconds.",
        };
    }

    HILTI_OPERATOR(hilti, interval::CtorSignedIntegerSecs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSignedIntegerSecs);

class CtorUnsignedIntegerNs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "interval_ns",
            .param0 =
                {
                    .type = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(type::Wildcard())},
                },
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Creates an interval interpreting the argument as number of nanoseconds.",
        };
    }

    HILTI_OPERATOR(hilti, interval::CtorUnsignedIntegerNs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsignedIntegerNs);

class CtorUnsignedIntegerSecs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "interval",
            .param0 =
                {
                    .type = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(type::Wildcard())},
                },
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Creates an interval interpreting the argument as number of seconds.",
        };
    }

    HILTI_OPERATOR(hilti, interval::CtorUnsignedIntegerSecs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsignedIntegerSecs);

class CtorRealSecs : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "interval",
            .param0 =
                {
                    .type = {.kind = parameter::Kind::In, .type = builder->typeReal()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "interval",
            .doc = "Creates an interval interpreting the argument as number of seconds.",
        };
    }

    HILTI_OPERATOR(hilti, interval::CtorRealSecs)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorRealSecs);

class Seconds : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .member = "seconds",
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "interval",
            .doc = R"(
Returns the interval as a real value representing seconds.
)",
        };
    }

    HILTI_OPERATOR(hilti, interval::Seconds);
};
HILTI_OPERATOR_IMPLEMENTATION(Seconds);

class Nanoseconds : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeInterval()},
            .member = "nanoseconds",
            .result = {.constness = Constness::Const, .type = builder->typeSignedInteger(64)},
            .ns = "interval",
            .doc = R"(
Returns the interval as an integer value representing nanoseconds.
)",
        };
    }

    HILTI_OPERATOR(hilti, interval::Nanoseconds);
};
HILTI_OPERATOR_IMPLEMENTATION(Nanoseconds);

} // namespace interval
} // namespace
