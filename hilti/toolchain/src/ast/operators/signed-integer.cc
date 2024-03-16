// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace signed_integer {

inline UnqualifiedType* widestTypeSigned(Builder* builder, const Expressions& operands) {
    unsigned int w1 = 0;
    unsigned int w2 = 0;

    if ( auto t = operands[0]->type()->type()->tryAs<type::SignedInteger>() )
        w1 = t->width();
    else if ( auto t = operands[0]->type()->type()->tryAs<type::UnsignedInteger>() )
        w1 = t->width();

    if ( auto t = operands[1]->type()->type()->tryAs<type::SignedInteger>() )
        w2 = t->width();
    else if ( auto t = operands[1]->type()->type()->tryAs<type::UnsignedInteger>() )
        w2 = t->width();

    if ( ! (w1 && w2) )
        return nullptr;

    const bool is_ctor1 = operands[0]->isA<expression::Ctor>();
    const bool is_ctor2 = operands[1]->isA<expression::Ctor>();

    if ( is_ctor1 && ! is_ctor2 )
        return builder->typeSignedInteger(w2);

    if ( is_ctor2 && ! is_ctor1 )
        return builder->typeSignedInteger(w1);

    return builder->typeSignedInteger(std::max(w1, w2));
}

class DecrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DecrPostfix,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Decrements the value, returning the old value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, signed_integer::DecrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(DecrPostfix);


class DecrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DecrPrefix,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Increments the value, returning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, signed_integer::DecrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(DecrPrefix);


class IncrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPostfix,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Increments the value, returning the old value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, signed_integer::IncrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPostfix);


class IncrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPrefix,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Increments the value, returning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, signed_integer::IncrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPrefix);


class SignNeg : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SignNeg,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Inverts the sign of the integer.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, signed_integer::SignNeg)
};
HILTI_OPERATOR_IMPLEMENTATION(SignNeg);


class Difference : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Difference,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int<*>",
            .ns = "signed_integer",
            .doc = "Computes the difference between the two integers.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeSigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Difference)
};
HILTI_OPERATOR_IMPLEMENTATION(Difference);


class DifferenceAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DifferenceAssign,
            .op0 = {parameter::Kind::InOut, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Decrements the first value by the second, assigning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto op1 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::DifferenceAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(DifferenceAssign);


class Division : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Division,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int<*>",
            .ns = "signed_integer",
            .doc = "Divides the first integer by the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeSigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Division)
};
HILTI_OPERATOR_IMPLEMENTATION(Division);


class DivisionAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DivisionAssign,
            .op0 = {parameter::Kind::InOut, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Divides the first value by the second, assigning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto op1 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::DivisionAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(DivisionAssign);


class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "signed_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);


class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Greater,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "signed_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Greater)
};
HILTI_OPERATOR_IMPLEMENTATION(Greater);


class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::GreaterEqual,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "signed_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);


class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Lower,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "signed_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);


class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::LowerEqual,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "signed_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);


class Modulo : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Modulo,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int<*>",
            .ns = "signed_integer",
            .doc = "Computes the modulus of the first integer divided by the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeSigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Modulo)
};
HILTI_OPERATOR_IMPLEMENTATION(Modulo);


class Multiple : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Multiple,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int<*>",
            .ns = "signed_integer",
            .doc = "Multiplies the first integer by the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeSigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Multiple)
};
HILTI_OPERATOR_IMPLEMENTATION(Multiple);


class MultipleAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MultipleAssign,
            .op0 = {parameter::Kind::InOut, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Multiplies the first value by the second, assigning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto op1 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::MultipleAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(MultipleAssign);


class Power : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Power,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int<*>",
            .ns = "signed_integer",
            .doc = "Computes the first integer raised to the power of the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeSigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Power)
};
HILTI_OPERATOR_IMPLEMENTATION(Power);


class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Sum,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int<*>",
            .ns = "signed_integer",
            .doc = "Computes the sum of the integers.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeSigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum);


class SumAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SumAssign,
            .op0 = {parameter::Kind::InOut, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result_doc = "int",
            .ns = "signed_integer",
            .doc = "Increments the first integer by the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto op1 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::SumAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssign);


class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "signed_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        auto op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeSigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, signed_integer::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);


class CastToSigned : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(
                        builder->qualifiedType(builder->typeSignedInteger(type::Wildcard()), Constness::Const))},
            .result_doc = "int<*>",
            .ns = "signed_integer",
            .doc = "Converts the value into a different signed integer type, accepting any loss of information.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, signed_integer::CastToSigned)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToSigned);


class CastToUnsigned : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(
                        builder->qualifiedType(builder->typeUnsignedInteger(type::Wildcard()), Constness::Const))},
            .result_doc = "uint<*>",
            .ns = "signed_integer",
            .doc = "Converts the value into an unsigned integer type, accepting any loss of information.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, signed_integer::CastToUnsigned)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToUnsigned);


class CastToReal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeReal(), Constness::Const))},
            .result = {Constness::Const, builder->typeReal()},
            .ns = "signed_integer",
            .doc = "Converts the value into a real, accepting any loss of information.",
        };
    }

    HILTI_OPERATOR(hilti, signed_integer::CastToReal)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToReal);


class CastToEnum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeEnum(type::Wildcard()), Constness::Const))},
            .result_doc = "enum<*>",
            .ns = "signed_integer",
            .doc =
                "Converts the value into an enum instance. The value does *not* need to correspond to "
                "any of the target type's enumerator labels.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, signed_integer::CastToEnum)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToEnum);


class CastToInterval : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeInterval(), Constness::Const))},
            .result = {Constness::Const, builder->typeInterval()},
            .ns = "signed_integer",
            .doc = "Interprets the value as number of seconds.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CastToInterval)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToInterval);


class CastToBool : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeBool(), Constness::Const))},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "signed_integer",
            .doc = "Converts the value to a boolean by comparing against zero",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CastToBool)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToBool);


class CtorSigned8 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "int8",
            .param0 = {.type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeSignedInteger(8)},
            .ns = "signed_integer",
            .doc = "Creates a 8-bit signed integer value.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CtorSigned8)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned8);

class CtorSigned16 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "int16",
            .param0 = {.type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeSignedInteger(16)},
            .ns = "signed_integer",
            .doc = "Creates a 16-bit signed integer value.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CtorSigned16)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned16);

class CtorSigned32 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "int32",
            .param0 = {.type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeSignedInteger(32)},
            .ns = "signed_integer",
            .doc = "Creates a 32-bit signed integer value.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CtorSigned32)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned32);

class CtorSigned64 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "int64",
            .param0 = {.type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeSignedInteger(64)},
            .ns = "signed_integer",
            .doc = "Creates a 64-bit signed integer value.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CtorSigned64)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned64);

class CtorUnsigned8 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "int8",
            .param0 = {.type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeSignedInteger(8)},
            .ns = "signed_integer",
            .doc = "Creates a 8-bit signed integer value.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CtorUnsigned8)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned8);

class CtorUnsigned16 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "int16",
            .param0 = {.type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeSignedInteger(16)},
            .ns = "signed_integer",
            .doc = "Creates a 16-bit signed integer value.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CtorUnsigned16)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned16);

class CtorUnsigned32 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "int32",
            .param0 = {.type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeSignedInteger(32)},
            .ns = "signed_integer",
            .doc = "Creates a 32-bit signed integer value.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CtorUnsigned32)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned32);

class CtorUnsigned64 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "int64",
            .param0 = {.type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeSignedInteger(64)},
            .ns = "signed_integer",
            .doc = "Creates a 64-bit signed integer value.",
        };
    }
    HILTI_OPERATOR(hilti, signed_integer::CtorUnsigned64)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned64);

} // namespace signed_integer
} // namespace
