// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace enum_ {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeEnum(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeEnum(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "enum_",
            .doc = "Compares two enum values.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, enum_::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeEnum(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeEnum(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "enum_",
            .doc = "Compares two enum values.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, enum_::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class CastToSignedInteger : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeEnum(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(
                        builder->qualifiedType(builder->typeSignedInteger(type::Wildcard()), Constness::Const))},
            .result_doc = "int",
            .ns = "enum_",
            .doc =
                "Casts an enum value into a signed integer. If the enum value is ``Undef``, this will return ``-1``.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, enum_::CastToSignedInteger)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToSignedInteger);

class CastToUnsignedInteger : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Cast,
            .op0 = {parameter::Kind::In, builder->typeEnum(type::Wildcard())},
            .op1 = {parameter::Kind::In,
                    builder->typeType(
                        builder->qualifiedType(builder->typeUnsignedInteger(type::Wildcard()), Constness::Const))},
            .result_doc = "uint",
            .ns = "enum_",
            .doc =
                "Casts an enum value into a unsigned integer. This will throw an exception if the enum value is "
                "``Undef``.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[1]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, enum_::CastToUnsignedInteger)
};
HILTI_OPERATOR_IMPLEMENTATION(CastToUnsignedInteger);

class CtorSigned : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .self = {parameter::Kind::In, builder->ctorType(builder->typeEnum(type::Wildcard()))},
            .param0 =
                {
                    .name = "value",
                    .type = {parameter::Kind::In, builder->typeSignedInteger(type::Wildcard())},
                },
            .result_doc = "enum value",
            .ns = "enum_",
            .doc = R"(
Instantiates an enum instance initialized from a signed integer value. The value does
*not* need to correspond to any of the type's enumerator labels.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, enum_::CtorSigned)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorSigned);

class CtorUnsigned : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .self = {parameter::Kind::In, builder->ctorType(builder->typeEnum(type::Wildcard()))},
            .param0 =
                {
                    .name = "value",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(type::Wildcard())},
                },
            .result_doc = "enum value",
            .ns = "enum_",
            .doc = R"(
Instantiates an enum instance initialized from an unsigned integer
value. The value does *not* need to correspond to any of the type's
enumerator labels. It must not be larger than the maximum that a
*signed* 64-bit integer value can represent.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, enum_::CtorUnsigned)
};
HILTI_OPERATOR_IMPLEMENTATION(CtorUnsigned);

class HasLabel : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeEnum(type::Wildcard())},
            .member = "has_label",
            .result = {Constness::Const, builder->typeBool()},
            .ns = "enum_",
            .doc = R"(
Returns *true* if the value of *op1* corresponds to a known enum label (other
than ``Undef``), as defined by its type.
)",
        };
    }

    HILTI_OPERATOR(hilti, enum_::HasLabel);
};
HILTI_OPERATOR_IMPLEMENTATION(HasLabel);

} // namespace enum_
} // namespace
