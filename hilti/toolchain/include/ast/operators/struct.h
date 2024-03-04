// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti {

namespace operator_ {
HILTI_NODE_OPERATOR(hilti, struct_, HasMember)
HILTI_NODE_OPERATOR(hilti, struct_, MemberCall);
HILTI_NODE_OPERATOR(hilti, struct_, MemberConst)
HILTI_NODE_OPERATOR(hilti, struct_, MemberNonConst)
HILTI_NODE_OPERATOR(hilti, struct_, TryMember)
HILTI_NODE_OPERATOR(hilti, struct_, Unset)
} // namespace operator_

namespace struct_ {

class MemberCall final : public Operator {
public:
    MemberCall(const std::shared_ptr<declaration::Field>& fdecl);
    ~MemberCall() final;

    auto declaration() const { return _fdecl.lock(); }

    operator_::Signature signature(Builder* builder) const final;
    Result<ResolvedOperatorPtr> instantiate(Builder* builder, Expressions operands, const Meta& meta) const final;

    std::string name() const final { return "struct::MemberCall"; }

private:
    std::weak_ptr<declaration::Field> _fdecl;
};

} // namespace struct_
} // namespace hilti
