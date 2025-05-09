// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/union.h>
#include <hilti/ast/types/unknown.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace union_ {

QualifiedType* itemType(Builder* builder, const Expressions& operands) {
    if ( auto* field =
             operands[0]->type()->type()->as<type::Union>()->field(operands[1]->as<expression::Member>()->id()) )
        return field->type();
    else
        return builder->qualifiedType(builder->typeUnknown(), Constness::Const);
}

void checkName(expression::ResolvedOperator* op) {
    const auto& id = op->op1()->as<expression::Member>()->id();
    if ( ! op->op0()->type()->type()->as<type::Union>()->field(id) )
        op->addError(util::fmt("type does not have field '%s'", id));
}

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeUnion(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnion(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "union_",
            .doc = "Compares two unions element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, union_::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeUnion(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnion(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "union_",
            .doc = "Compares two unions element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, union_::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class MemberConst : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Member,
            .priority = Priority::Low, // prefer the non-const version
            .op0 = {parameter::Kind::In, builder->typeUnion(type::Wildcard()), "<union>"},
            .op1 = {parameter::Kind::In, builder->typeMember(type::Wildcard()), "<field>"},
            .result_doc = "<field type>",
            .ns = "union_",
            .doc =
                R"(
Retrieves the value of a union's field. If the union does not have the field set,
this triggers an exception.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return itemType(builder, operands);
    }

    void validate(expression::ResolvedOperator* n) const final { checkName(n); }

    HILTI_OPERATOR(hilti, union_::MemberConst)
};
HILTI_OPERATOR_IMPLEMENTATION(MemberConst);

class MemberNonConst : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Member,
            .op0 = {parameter::Kind::InOut, builder->typeUnion(type::Wildcard()), "<union>"},
            .op1 = {parameter::Kind::In, builder->typeMember(type::Wildcard()), "<field>"},
            .result_doc = "<field type>",
            .ns = "union_",
            .doc = R"(
Retrieves the value of a union's field. If the union does not have the field set,
this triggers an exception unless the value is only being assigned to.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return itemType(builder, operands)->recreateAsLhs(builder->context());
    }

    void validate(expression::ResolvedOperator* n) const final { checkName(n); }

    HILTI_OPERATOR(hilti, union_::MemberNonConst)
};
HILTI_OPERATOR_IMPLEMENTATION(MemberNonConst);

class HasMember : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::HasMember,
            .op0 = {parameter::Kind::In, builder->typeUnion(type::Wildcard()), "<union>"},
            .op1 = {parameter::Kind::In, builder->typeMember(type::Wildcard()), "<field>"},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "union_",
            .doc = "Returns true if the union's field is set.",
        };
    }

    void validate(expression::ResolvedOperator* n) const final { checkName(n); }

    HILTI_OPERATOR(hilti, union_::HasMember)
};
HILTI_OPERATOR_IMPLEMENTATION(HasMember);

} // namespace union_
} // namespace
