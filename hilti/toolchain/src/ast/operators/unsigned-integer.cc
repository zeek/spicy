// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace unsigned_integer {

inline UnqualifiedType* widestTypeUnsigned(Builder* builder, const Expressions& operands) {
    unsigned int w1 = 0;
    unsigned int w2 = 0;

    if ( auto* t = operands[0]->type()->type()->tryAs<type::SignedInteger>() )
        w1 = t->width();
    else if ( auto* t = operands[0]->type()->type()->tryAs<type::UnsignedInteger>() )
        w1 = t->width();

    if ( auto* t = operands[1]->type()->type()->tryAs<type::SignedInteger>() )
        w2 = t->width();
    else if ( auto* t = operands[1]->type()->type()->tryAs<type::UnsignedInteger>() )
        w2 = t->width();

    if ( ! (w1 && w2) )
        return nullptr;

    const bool is_ctor1 = operands[0]->isA<expression::Ctor>();
    const bool is_ctor2 = operands[1]->isA<expression::Ctor>();

    if ( is_ctor1 && ! is_ctor2 )
        return builder->typeUnsignedInteger(w2);

    if ( is_ctor2 && ! is_ctor1 )
        return builder->typeUnsignedInteger(w1);

    return builder->typeUnsignedInteger(std::max(w1, w2));
}

inline void validateShiftAmount(expression::ResolvedOperator* n) {
    if ( auto* expr = n->op1()->tryAs<expression::Ctor>() ) {
        auto* ctor = expr->ctor();
        if ( auto* coerced = ctor->tryAs<ctor::Coerced>() )
            ctor = coerced->coercedCtor();

        if ( auto* i = ctor->tryAs<ctor::UnsignedInteger>() ) {
            if ( i->value() >= n->op0()->type()->type()->as<type::UnsignedInteger>()->width() )
                n->addError("shift amount must be smaller than operand's width", n->location());
        }
    }
}

class DecrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DecrPostfix,
            .op0 = {parameter::Kind::InOut, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Decrements the value, returning the old value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::DecrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(DecrPostfix);


class DecrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DecrPrefix,
            .op0 = {parameter::Kind::InOut, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Increments the value, returning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::DecrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(DecrPrefix);


class IncrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPostfix,
            .op0 = {parameter::Kind::InOut, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Increments the value, returning the old value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::IncrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPostfix);


class IncrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPrefix,
            .op0 = {parameter::Kind::InOut, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Increments the value, returning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::IncrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPrefix);


class SignNeg : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SignNeg,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Inverts the sign of the integer.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(builder->typeSignedInteger(
                                          operands[0]->type()->type()->as<type::UnsignedInteger>()->width()),
                                      Constness::Const);
    }

    HILTI_OPERATOR(hilti, unsigned_integer::SignNeg)
};
HILTI_OPERATOR_IMPLEMENTATION(SignNeg);


class Difference : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Difference,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Computes the difference between the two integers.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Difference)
};
HILTI_OPERATOR_IMPLEMENTATION(Difference);


class DifferenceAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DifferenceAssign,
            .op0 = {parameter::Kind::InOut, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Decrements the first value by the second, assigning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto* op1 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::DifferenceAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(DifferenceAssign);


class Division : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Division,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Divides the first integer by the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Division)
};
HILTI_OPERATOR_IMPLEMENTATION(Division);


class DivisionAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::DivisionAssign,
            .op0 = {parameter::Kind::InOut, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Divides the first value by the second, assigning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto* op1 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::DivisionAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(DivisionAssign);


class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "unsigned_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);


class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Greater,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "unsigned_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Greater)
};
HILTI_OPERATOR_IMPLEMENTATION(Greater);


class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::GreaterEqual,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "unsigned_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);


class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Lower,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "unsigned_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);


class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::LowerEqual,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "unsigned_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);


class Modulo : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Modulo,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Computes the modulus of the first integer divided by the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Modulo)
};
HILTI_OPERATOR_IMPLEMENTATION(Modulo);


class Multiple : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Multiple,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Multiplies the first integer by the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Multiple)
};
HILTI_OPERATOR_IMPLEMENTATION(Multiple);


class MultipleAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MultipleAssign,
            .op0 = {parameter::Kind::InOut, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Multiplies the first value by the second, assigning the new value.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto* op1 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::MultipleAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(MultipleAssign);


class Power : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Power,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Computes the first integer raised to the power of the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Power)
};
HILTI_OPERATOR_IMPLEMENTATION(Power);


class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Sum,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Computes the sum of the integers.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum);


class SumAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SumAssign,
            .op0 = {parameter::Kind::InOut, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint",
            .ns = "unsigned_integer",
            .doc = "Increments the first integer by the second.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto* op1 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::SumAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssign);


class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "unsigned_integer",
            .doc = "Compares the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class Negate : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Negate,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Computes the bit-wise negation of the integer.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::Negate)
};
HILTI_OPERATOR_IMPLEMENTATION(Negate);

class BitAnd : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::BitAnd,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Computes the bit-wise 'and' of the two integers.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    HILTI_OPERATOR(hilti, unsigned_integer::BitAnd)
};
HILTI_OPERATOR_IMPLEMENTATION(BitAnd);

class BitOr : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::BitOr,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Computes the bit-wise 'or' of the two integers.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::BitOr)
};
HILTI_OPERATOR_IMPLEMENTATION(BitOr);

class BitXor : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::BitXor,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Computes the bit-wise 'xor' of the two integers.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(widestTypeUnsigned(builder, operands), Constness::Const);
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        auto* op1 = builder->typeOperandListOperand(parameter::Kind::In, widestTypeUnsigned(builder, operands));
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, unsigned_integer::BitXor)
};
HILTI_OPERATOR_IMPLEMENTATION(BitXor);


class ShiftLeft : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::ShiftLeft,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Shifts the integer to the left by the given number of bits.",
        };
    }

    void validate(expression::ResolvedOperator* n) const override { validateShiftAmount(n); }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::ShiftLeft)
};
HILTI_OPERATOR_IMPLEMENTATION(ShiftLeft);


class ShiftRight : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::ShiftRight,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Shifts the integer to the right by the given number of bits.",
        };
    }

    void validate(expression::ResolvedOperator* n) const override { validateShiftAmount(n); }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::ShiftRight)
};
HILTI_OPERATOR_IMPLEMENTATION(ShiftRight);

class CastToUnsigned : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(
                        builder->qualifiedType(builder->typeUnsignedInteger(type::Wildcard()), Constness::Const))},
            .result_doc = "uint<*>",
            .ns = "unsigned_integer",
            .doc = "Converts the value into a different unsigned integer type, accepting any loss of information.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::CastToUnsigned)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToUnsigned);


class CastToSigned : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(
                        builder->qualifiedType(builder->typeSignedInteger(type::Wildcard()), Constness::Const))},
            .result_doc = "int<*>",
            .ns = "unsigned_integer",
            .doc = "Converts the value into a signed integer type, accepting any loss of information.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::CastToSigned)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToSigned);


class CastToReal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeReal(), Constness::Const))},
            .result = {Constness::Const, builder->typeReal()},
            .ns = "unsigned_integer",
            .doc = "Converts the value into a real, accepting any loss of information.",
        };
    }

    HILTI_OPERATOR(hilti, unsigned_integer::CastToReal)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToReal);


class CastToEnum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeEnum(type::Wildcard()), Constness::Const))},
            .result_doc = "enum<*>",
            .ns = "unsigned_integer",
            .doc =
                "Converts the value into an enum instance. The value does *not* need to correspond to "
                "any of the target type's enumerator labels.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, unsigned_integer::CastToEnum)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToEnum);


class CastToInterval : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeInterval(), Constness::Const))},
            .result = {Constness::Const, builder->typeInterval()},
            .ns = "unsigned_integer",
            .doc = "Interprets the value as number of seconds.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CastToInterval)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToInterval);


class CastToTime : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeTime(), Constness::Const))},
            .result = {Constness::Const, builder->typeTime()},
            .ns = "unsigned_integer",
            .doc = "Interprets the value as number of seconds.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CastToTime)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToTime);


class CastToBool : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(builder->qualifiedType(builder->typeBool(), Constness::Const))},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "unsigned_integer",
            .doc = "Converts the value to a boolean by comparing against zero",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CastToBool)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToBool);


class CtorSigned8 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "uint8",
            .param0 = {.type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeUnsignedInteger(8)},
            .ns = "unsigned_integer",
            .doc = "Creates a 8-bit unsigned integer value.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CtorSigned8)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned8);

class CtorSigned16 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "uint16",
            .param0 = {.type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeUnsignedInteger(16)},
            .ns = "unsigned_integer",
            .doc = "Creates a 16-bit unsigned integer value.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CtorSigned16)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned16);

class CtorSigned32 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "uint32",
            .param0 = {.type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeUnsignedInteger(32)},
            .ns = "unsigned_integer",
            .doc = "Creates a 32-bit unsigned integer value.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CtorSigned32)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned32);

class CtorSigned64 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "uint64",
            .param0 = {.type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeUnsignedInteger(64)},
            .ns = "unsigned_integer",
            .doc = "Creates a 64-bit unsigned integer value.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CtorSigned64)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned64);

class CtorUnsigned8 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "uint8",
            .param0 = {.type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeUnsignedInteger(8)},
            .ns = "unsigned_integer",
            .doc = "Creates a 8-bit unsigned integer value.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CtorUnsigned8)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned8);

class CtorUnsigned16 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "uint16",
            .param0 = {.type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeUnsignedInteger(16)},
            .ns = "unsigned_integer",
            .doc = "Creates a 16-bit unsigned integer value.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CtorUnsigned16)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned16);

class CtorUnsigned32 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "uint32",
            .param0 = {.type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeUnsignedInteger(32)},
            .ns = "unsigned_integer",
            .doc = "Creates a 32-bit unsigned integer value.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CtorUnsigned32)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned32);

class CtorUnsigned64 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "uint64",
            .param0 = {.type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())}},
            .result = {Constness::Const, builder->typeUnsignedInteger(64)},
            .ns = "unsigned_integer",
            .doc = "Creates a 64-bit unsigned integer value.",
        };
    }
    HILTI_OPERATOR(hilti, unsigned_integer::CtorUnsigned64)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned64);

} // namespace unsigned_integer
} // namespace
