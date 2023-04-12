// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expressions/id.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/string.h>

namespace hilti::operator_ {
OPERATOR_DECLARE_ONLY(function, Call)
}

namespace hilti::operator_::function {

class Call : public hilti::expression::ResolvedOperatorBase {
public:
    using hilti::expression::ResolvedOperatorBase::ResolvedOperatorBase;

    struct Operator : public hilti::trait::isOperator {
        Operator(const Scope::Referee& r, const type::Function& ftype) {
            auto op0 = operator_::Operand{{}, type::Any()}; // IDs won't be resolved
            auto op1 = operator_::Operand{{}, type::OperandList::fromParameters(ftype.parameters())};
            _referee = r;
            _operands = {op0, op1};
            _result = ftype.result().type();
        }

        static operator_::Kind kind() { return operator_::Kind::Call; }
        const std::vector<operator_::Operand>& operands() const { return _operands; }
        Type result(const hilti::node::Range<Expression>& /* ops */) const { return _result; }
        bool isLhs() const { return false; }
        auto priority() const { return hilti::operator_::Priority::Normal; }
        void validate(const expression::ResolvedOperator& /* i */, operator_::position_t /* p */) const {}
        std::string doc() const { return "<dynamic - no doc>"; }
        std::string docNamespace() const { return "<dynamic - no ns>"; }

        Expression instantiate(const std::vector<Expression>& operands, const Meta& meta) const {
            auto ops = std::vector<Expression>{expression::ResolvedID(ID(_referee.qualified), NodeRef(_referee.node),
                                                                      _referee.node->meta()),
                                               operands[1]};

            auto ro = expression::ResolvedOperator(Call(*this, ops, meta));
            ro.setMeta(meta);
            return std::move(ro);
        }

    private:
        Scope::Referee _referee;
        std::vector<operator_::Operand> _operands;
        Type _result;
    };
};

} // namespace hilti::operator_::function
