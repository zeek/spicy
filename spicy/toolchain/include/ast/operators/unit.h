// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/node.h>

namespace spicy {

namespace operator_ {
SPICY_NODE_OPERATOR(unit, Backtrack)
SPICY_NODE_OPERATOR(unit, ConnectFilter)
SPICY_NODE_OPERATOR(unit, ContextConst)
SPICY_NODE_OPERATOR(unit, ContextNonConst)
SPICY_NODE_OPERATOR(unit, Find)
SPICY_NODE_OPERATOR(unit, Forward)
SPICY_NODE_OPERATOR(unit, ForwardEod)
SPICY_NODE_OPERATOR(unit, HasMember)
SPICY_NODE_OPERATOR(unit, Input)
SPICY_NODE_OPERATOR(unit, MemberCall);
SPICY_NODE_OPERATOR(unit, MemberConst)
SPICY_NODE_OPERATOR(unit, MemberNonConst)
SPICY_NODE_OPERATOR(unit, Offset)
SPICY_NODE_OPERATOR(unit, Position)
SPICY_NODE_OPERATOR(unit, SetInput)
SPICY_NODE_OPERATOR(unit, TryMember)
SPICY_NODE_OPERATOR(unit, Unset)
} // namespace operator_

namespace unit {

class MemberCall final : public hilti::Operator {
public:
    MemberCall(type::unit::item::Field* field);
    ~MemberCall() final;

    auto field() const { return _field; }

    hilti::operator_::Signature signature(hilti::Builder* builder) const final;
    hilti::Result<hilti::expression::ResolvedOperator*> instantiate(hilti::Builder* builder, Expressions operands,
                                                                    Meta meta) const final;

    std::string name() const final { return "unit::MemberCall"; }

private:
    type::unit::item::Field* _field = nullptr;
};

} // namespace unit
} // namespace spicy
