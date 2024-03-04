// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

#include <spicy/ast/forward.h>

namespace spicy {

namespace operator_ {
HILTI_NODE_OPERATOR(spicy, unit, Backtrack)
HILTI_NODE_OPERATOR(spicy, unit, ConnectFilter)
HILTI_NODE_OPERATOR(spicy, unit, ContextConst)
HILTI_NODE_OPERATOR(spicy, unit, ContextNonConst)
HILTI_NODE_OPERATOR(spicy, unit, Find)
HILTI_NODE_OPERATOR(spicy, unit, Forward)
HILTI_NODE_OPERATOR(spicy, unit, ForwardEod)
HILTI_NODE_OPERATOR(spicy, unit, HasMember)
HILTI_NODE_OPERATOR(spicy, unit, Input)
HILTI_NODE_OPERATOR(spicy, unit, MemberCall);
HILTI_NODE_OPERATOR(spicy, unit, MemberConst)
HILTI_NODE_OPERATOR(spicy, unit, MemberNonConst)
HILTI_NODE_OPERATOR(spicy, unit, Offset)
HILTI_NODE_OPERATOR(spicy, unit, Position)
HILTI_NODE_OPERATOR(spicy, unit, SetInput)
HILTI_NODE_OPERATOR(spicy, unit, TryMember)
HILTI_NODE_OPERATOR(spicy, unit, Unset)
} // namespace operator_

namespace unit {

class MemberCall final : public hilti::Operator {
public:
    MemberCall(const type::unit::item::FieldPtr& field);
    ~MemberCall() final;

    auto field() const { return _field.lock(); }

    hilti::operator_::Signature signature(hilti::Builder* builder) const final;
    hilti::Result<hilti::ResolvedOperatorPtr> instantiate(hilti::Builder* builder, Expressions operands,
                                                          const Meta& meta) const final;

    std::string name() const final { return "unit::MemberCall"; }

private:
    std::weak_ptr<type::unit::item::Field> _field;
};

} // namespace unit
} // namespace spicy
