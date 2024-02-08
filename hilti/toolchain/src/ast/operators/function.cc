// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/operators/function.h>

using namespace hilti;
using namespace hilti::operator_;

hilti::function::Call::~Call() {}

operator_::Signature hilti::function::Call::signature(Builder* builder) const {
    auto fdecl = _fdecl.lock();
    assert(fdecl);

    auto params = type::OperandList::fromParameters(builder->context(), fdecl->function()->ftype()->parameters());
    auto result = fdecl->function()->ftype()->result();
    auto ftype = builder->typeFunction(type::Wildcard());
    ftype->setFunctionNameForPrinting(fdecl->id());

    return {
        .kind = Kind::Call,
        .op0 = {parameter::Kind::In, std::move(ftype)}, // will be found through scope lookup, not by name matching
        .op1 = {parameter::Kind::In, params},
        .result = {result->isConstant() ? Const : NonConst, result->type()},
        .skip_doc = true,
    };
}

Result<ResolvedOperatorPtr> hilti::function::Call::instantiate(Builder* builder, Expressions operands,
                                                               const Meta& meta) const {
    auto fdecl = _fdecl.lock();
    assert(fdecl);

    assert(fdecl->fullyQualifiedID());
    auto callee = operands[0]->as<expression::Name>(); // builder->expressionName(fdecl->fullyQualifiedID(), meta);
    callee->setResolvedDeclarationIndex(builder->context(),
                                        builder->context()->register_(
                                            fdecl->as<Declaration>())); // will be used immediately, cannot wait for
                                                                        // resolver

    auto args = operands[1];
    auto result = fdecl->function()->ftype()->result();

    return {operator_::function::Call::create(builder->context(), this, result, {std::move(callee), std::move(args)},
                                              meta)};
}
