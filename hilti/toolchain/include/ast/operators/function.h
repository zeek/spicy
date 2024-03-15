// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/operators/common.h>

namespace hilti {

namespace operator_ {
HILTI_NODE_OPERATOR(function, Call); // AST node for instantiated call operator
}

namespace function {

class Call final : public Operator {
public:
    Call(declaration::Function* f) : Operator(f->meta(), false), _fdecl(f) {}

    operator_::Signature signature(Builder* builder) const final;

    Result<expression::ResolvedOperator*> instantiate(Builder* builder, Expressions operands, Meta meta) const final;

    std::string name() const final { return "function::Call"; }

private:
    friend class declaration::Function;

    declaration::Function* _fdecl = nullptr;
};

} // namespace function

} // namespace hilti
