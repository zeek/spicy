// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <hilti/ast/operators/common.h>

#include <spicy/ast/forward.h>

namespace spicy {

namespace operator_ {
HILTI_NODE_OPERATOR(spicy, unit, MemberCall); // AST node for instantiated call operator
}

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
