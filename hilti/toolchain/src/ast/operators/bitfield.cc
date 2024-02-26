// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <string>
#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/unknown.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace bitfield {

QualifiedTypePtr _itemType(Builder* builder, const Expressions& operands) {
    if ( auto range =
             operands[0]->type()->type()->as<type::Bitfield>()->bits(operands[1]->as<expression::Member>()->id()) )
        return range->itemType();
    else
        return builder->qualifiedType(builder->typeUnknown(), Constness::Const);
}

void _checkName(expression::ResolvedOperator* op) {
    auto id = op->op1()->as<expression::Member>()->id();
    if ( ! op->op0()->type()->type()->as<type::Bitfield>()->bits(id) )
        op->addError(util::fmt("bitfield type does not have attribute '%s'", id));
}

class Member : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {.kind = Kind::Member,
                .op0 = {parameter::Kind::In, builder->typeBitfield(type::Wildcard()), "<bitfield>"},
                .op1 = {parameter::Kind::In, builder->typeMember(type::Wildcard()), "<name>"},
                .result_doc = "<field type>",
                .ns = "bitfield",
                .doc = R"(
Retrieves the value of a bitfield's attribute. This is the value of the
corresponding bits inside the underlying integer value, shifted to the very
right.
)"};
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return _itemType(builder, operands);
    }

    void validate(expression::ResolvedOperator* n) const final { _checkName(n); }

    HILTI_OPERATOR(hilti, bitfield::Member)
};
HILTI_OPERATOR_IMPLEMENTATION(Member);

class HasMember : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::HasMember,
            .op0 = {parameter::Kind::In, builder->typeBitfield(type::Wildcard()), "<bitfield>"},
            .op1 = {parameter::Kind::In, builder->typeMember(type::Wildcard()), "<name>"},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "bitfield",
            .doc = "Returns true if the bitfield's element has a value.",
        };
    }

    void validate(expression::ResolvedOperator* n) const final { _checkName(n); }

    HILTI_OPERATOR(hilti, bitfield::HasMember)
};
HILTI_OPERATOR_IMPLEMENTATION(HasMember);

} // namespace bitfield
} // namespace
