// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace real {

class SignNeg : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SignNeg,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Inverts the sign of the real.",
        };
    }

    HILTI_OPERATOR(hilti, real::SignNeg)
};
HILTI_OPERATOR_IMPLEMENTATION(SignNeg);
class Difference : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Difference,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Returns the difference between the two values.",
        };
    }

    HILTI_OPERATOR(hilti, real::Difference)
};
HILTI_OPERATOR_IMPLEMENTATION(Difference);

class DifferenceAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DifferenceAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Subtracts the second value from the first, assigning the new value.",
        };
    }

    HILTI_OPERATOR(hilti, real::DifferenceAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(DifferenceAssign);

class Division : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Division,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Divides the first value by the second.",
        };
    }

    HILTI_OPERATOR(hilti, real::Division)
};
HILTI_OPERATOR_IMPLEMENTATION(Division);
class DivisionAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DivisionAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Divides the first value by the second, assigning the new value.",
        };
    }

    HILTI_OPERATOR(hilti, real::DivisionAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(DivisionAssign);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(hilti, real::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);
class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Greater,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(hilti, real::Greater)
};
HILTI_OPERATOR_IMPLEMENTATION(Greater);
class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::GreaterEqual,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(hilti, real::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);
class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Lower,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(hilti, real::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);
class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::LowerEqual,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(hilti, real::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);
class Modulo : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Modulo,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Computes the modulus of the first real divided by the second.",
        };
    }

    HILTI_OPERATOR(hilti, real::Modulo)
};
HILTI_OPERATOR_IMPLEMENTATION(Modulo);

class Multiple : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Multiple,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Multiplies the first real by the second.",
        };
    }

    HILTI_OPERATOR(hilti, real::Multiple)
};
HILTI_OPERATOR_IMPLEMENTATION(Multiple);

class MultipleAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MultipleAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Multiplies the first value by the second, assigning the new value.",
        };
    }

    HILTI_OPERATOR(hilti, real::MultipleAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(MultipleAssign);

class Power : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Power,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Computes the first real raised to the power of the second.",
        };
    }

    HILTI_OPERATOR(hilti, real::Power)
};
HILTI_OPERATOR_IMPLEMENTATION(Power);

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Sum,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Returns the sum of the reals.",
        };
    }

    HILTI_OPERATOR(hilti, real::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum);
class SumAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SumAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeReal()},
            .ns = "real",
            .doc = "Adds the first real to the second, assigning the new value.",
        };
    }

    HILTI_OPERATOR(hilti, real::SumAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssign);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .priority = Priority::Low, // avoid ambiguities with integer::Equal
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "real",
            .doc = "Compares the two reals.",
        };
    }

    HILTI_OPERATOR(hilti, real::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class CastToUnsignedInteger : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In,
                    .type = builder->typeType(
                        builder->qualifiedType(builder->typeUnsignedInteger(type::Wildcard()), Constness::Const))},
            .result_doc = "uint<*>",
            .ns = "real",
            .doc = "Converts the value to an unsigned integer type, accepting any loss of information.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, real::CastToUnsignedInteger)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToUnsignedInteger);


class CastToSignedInteger : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In,
                    .type = builder->typeType(
                        builder->qualifiedType(builder->typeSignedInteger(type::Wildcard()), Constness::Const))},
            .result_doc = "int<*>",
            .ns = "real",
            .doc = "Converts the value to a signed integer type, accepting any loss of information.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, real::CastToSignedInteger)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToSignedInteger);


class CastToTime : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In,
                    .type = builder->typeType(builder->qualifiedType(builder->typeTime(), Constness::Const))},
            .result = {.constness = Constness::Const, .type = builder->typeTime()},
            .ns = "real",
            .doc = "Interprets the value as number of seconds since the UNIX epoch.",
        };
    }

    HILTI_OPERATOR(hilti, real::CastToTime)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToTime);

class CastToInterval : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeReal()},
            .op1 = {.kind = parameter::Kind::In,
                    .type = builder->typeType(builder->qualifiedType(builder->typeInterval(), Constness::Const))},
            .result = {.constness = Constness::Const, .type = builder->typeInterval()},
            .ns = "real",
            .doc = "Interprets the value as number of seconds.",
        };
    }

    HILTI_OPERATOR(hilti, real::CastToInterval)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToInterval);

} // namespace real
} // namespace
