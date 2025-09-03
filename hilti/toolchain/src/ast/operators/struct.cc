// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <string>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/unknown.h>

using namespace hilti;
using namespace hilti::operator_;

hilti::struct_::MemberCall::MemberCall(declaration::Field* fdecl) : Operator(fdecl->meta(), false), _fdecl(fdecl) {}

hilti::struct_::MemberCall::~MemberCall() {}

operator_::Signature hilti::struct_::MemberCall::signature(Builder* builder) const {
    auto* ftype = _fdecl->type()->type()->as<type::Function>();
    auto* stype = _fdecl->parent(1)->as<type::Struct>();
    auto* params = type::OperandList::fromParameters(builder->context(), ftype->parameters());
    auto* result = ftype->result();

    return Signature{
        .kind = Kind::MemberCall,
        .self = {.kind = parameter::Kind::InOut, .type = nullptr, .doc = "", .external_type = stype},
        .op1 = {.kind = parameter::Kind::In, .type = builder->typeMember(ID(_fdecl->id()))},
        .op2 = {.kind = parameter::Kind::In, .type = params},
        .result = {.constness = result->constness(), .type = result->type()},
        .skip_doc = true,
    };
}

Result<expression::ResolvedOperator*> hilti::struct_::MemberCall::instantiate(Builder* builder, Expressions operands,
                                                                              Meta meta) const {
    auto* callee = operands[0];
    auto* member = operands[1];
    auto* args = operands[2];
    auto* result = _fdecl->type()->type()->as<type::Function>()->result();

    return {operator_::struct_::MemberCall::create(builder->context(), this, result, {callee, member, args},
                                                   std::move(meta))};
}

namespace {
namespace struct_ {

QualifiedType* itemType(Builder* builder, const Expressions& operands) {
    auto* stype = operands[0]->type()->type()->tryAs<type::Struct>();
    if ( ! stype )
        return builder->qualifiedType(builder->typeUnknown(), Constness::Const);

    if ( auto* field = stype->field(operands[1]->as<expression::Member>()->id()) )
        return field->type();
    else
        return builder->qualifiedType(builder->typeUnknown(), Constness::Const);
}

void checkName(expression::ResolvedOperator* op, bool check_optional = false) {
    const auto& id = op->op1()->as<expression::Member>()->id();
    auto* t = op->op0()->type()->type();

    if ( auto* x = t->tryAs<type::ValueReference>() )
        t = x->dereferencedType()->type();

    auto* stype = t->tryAs<type::Struct>();
    if ( ! stype ) {
        op->addError("type is not a struct");
        return;
    }

    auto* f = stype->field(id);
    if ( ! f ) {
        op->addError(util::fmt("type does not have field '%s'", id));
        return;
    }

    if ( check_optional && ! f->isOptional() )
        op->addError(util::fmt("field '%s' is not &optional", id));

    if ( f->isNoEmit() )
        op->addError(util::fmt("field '%s' cannot be accessed", id));
}

class Unset : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unset,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeStruct(type::Wildcard()), .doc = "<struct>"},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMember(type::Wildcard()), .doc = "<field>"},
            .result = {.constness = Constness::Const, .type = builder->typeVoid()},
            .ns = "struct",
            .doc = R"(
Clears an optional field.
)",
        };
    }

    void validate(expression::ResolvedOperator* n) const final { checkName(n, true); }

    HILTI_OPERATOR(hilti, struct_::Unset)
};
HILTI_OPERATOR_IMPLEMENTATION(Unset);

class MemberNonConst : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Member,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeStruct(type::Wildcard()), .doc = "<struct>"},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMember(type::Wildcard()), .doc = "<field>"},
            .result_doc = "<field type>",
            .ns = "struct",
            .doc = R"(
Retrieves the value of a struct's field. If the field does not have a value assigned,
it returns its ``&default`` expression if that has been defined; otherwise it
triggers an exception.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return itemType(builder, operands)->recreateAsLhs(builder->context());
    }

    void validate(expression::ResolvedOperator* n) const final { checkName(n); }

    HILTI_OPERATOR(hilti, struct_::MemberNonConst)
};
HILTI_OPERATOR_IMPLEMENTATION(MemberNonConst);

class MemberConst : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Member,
            .priority = Priority::Low, // prefer the non-const version
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStruct(type::Wildcard()), .doc = "<struct>"},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMember(type::Wildcard()), .doc = "<field>"},
            .result_doc = "<field type>",
            .ns = "struct",
            .doc = R"(
Retrieves the value of a struct's field. If the field does not have a value assigned,
it returns its ``&default`` expression if that has been defined; otherwise it
triggers an exception.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return itemType(builder, operands)->recreateAsConst(builder->context());
    }

    void validate(expression::ResolvedOperator* n) const final { checkName(n); }

    HILTI_OPERATOR(hilti, struct_::MemberConst)
};
HILTI_OPERATOR_IMPLEMENTATION(MemberConst);

class TryMember : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::TryMember,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeStruct(type::Wildcard()), .doc = "<struct>"},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMember(type::Wildcard()), .doc = "<field>"},
            .result_doc = "<field type>",
            .ns = "struct",
            .doc = R"(
Retrieves the value of a struct's field. If the field does not have a value
assigned, it returns its ``&default`` expression if that has been defined;
otherwise it signals a special non-error exception to the host application
(which will normally still lead to aborting execution, similar to the standard
dereference operator, unless the host application specifically handles this
exception differently).
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return itemType(builder, operands);
    }

    void validate(expression::ResolvedOperator* n) const final { checkName(n); }

    HILTI_OPERATOR(hilti, struct_::TryMember)
};
HILTI_OPERATOR_IMPLEMENTATION(TryMember);

class HasMember : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::HasMember,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStruct(type::Wildcard()), .doc = "<struct>"},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMember(type::Wildcard()), .doc = "<field>"},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "struct",
            .doc = "Returns true if the struct's field has a value assigned (not counting any ``&default``).",
        };
    }

    void validate(expression::ResolvedOperator* n) const final { checkName(n); }

    HILTI_OPERATOR(hilti, struct_::HasMember)
};
HILTI_OPERATOR_IMPLEMENTATION(HasMember);

} // namespace struct_
} // namespace
