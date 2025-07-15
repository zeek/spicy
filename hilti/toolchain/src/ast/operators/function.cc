// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/operators/function.h>

using namespace hilti;
using namespace hilti::operator_;

operator_::Signature hilti::function::Call::signature(Builder* builder) const {
    auto* params = type::OperandList::fromParameters(builder->context(), _fdecl->function()->ftype()->parameters());
    auto* result = _fdecl->function()->ftype()->result();
    auto* ftype = builder->typeFunction(type::Wildcard());
    ftype->setFunctionNameForPrinting(_fdecl->id());

    return Signature{
        .kind = Kind::Call,
        .op0 = {.kind = parameter::Kind::In, .type = ftype}, // will be found through scope lookup, not by name matching
        .op1 = {.kind = parameter::Kind::In, .type = params},
        .result = {.constness = result->isConstant() ? Constness::Const : Constness::Mutable, .type = result->type()},
        .skip_doc = true,
    };
}

Result<expression::ResolvedOperator*> hilti::function::Call::instantiate(Builder* builder, Expressions operands,
                                                                         Meta meta) const {
    assert(_fdecl->fullyQualifiedID());
    auto* callee = operands[0]->as<expression::Name>();
    callee->setResolvedDeclarationIndex(builder->context(),
                                        builder->context()->register_(
                                            _fdecl->as<Declaration>())); // will be used immediately, cannot wait for
                                                                         // resolver

    auto* args = operands[1];
    auto* result = _fdecl->function()->ftype()->result();

    return {operator_::function::Call::create(builder->context(), this, result, {callee, args}, std::move(meta))};
}
