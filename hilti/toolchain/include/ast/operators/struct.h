// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti {

namespace operator_ {
HILTI_NODE_OPERATOR(struct_, HasMember)
HILTI_NODE_OPERATOR(struct_, MemberCall);
HILTI_NODE_OPERATOR(struct_, MemberConst)
HILTI_NODE_OPERATOR(struct_, MemberNonConst)
HILTI_NODE_OPERATOR(struct_, TryMember)
HILTI_NODE_OPERATOR(struct_, Unset)
} // namespace operator_

namespace struct_ {

class MemberCall final : public Operator {
public:
    MemberCall(declaration::Field* fdecl);
    ~MemberCall() final;

    auto declaration() const { return _fdecl.get(); }

    operator_::Signature signature(Builder* builder) const final;
    Result<expression::ResolvedOperator*> instantiate(Builder* builder, Expressions operands, Meta meta) const final;

    std::string name() const final { return "struct::MemberCall"; }

private:
    node::RetainedPtr<declaration::Field> _fdecl = nullptr;
};

} // namespace struct_
} // namespace hilti
