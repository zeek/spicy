// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/ast/expressions/member.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::operator_ {

namespace struct_::detail {

// Returns an operand as a member expression.
static expression::Member memberExpression(const Expression& op) {
    if ( auto c = op.tryAs<expression::Coerced>() )
        return c->expression().as<expression::Member>();

    return op.as<expression::Member>();
}

// Checks if an operand refers to a valid field inside a struct.
static inline void checkName(const Expression& op0, const Expression& op1, Node& node, bool check_optional = false) {
    auto id = memberExpression(op1).id().local();
    auto f = op0.type().as<type::Struct>().field(id);

    if ( ! f ) {
        node.addError(util::fmt("type does not have field '%s'", id));
        return;
    }

    if ( check_optional && ! f->isOptional() )
        node.addError(util::fmt("field '%s' is not &optional", id));

    if ( f->isNoEmit() )
        node.addError(util::fmt("field '%s' cannot be accessed", id));
}

// Returns the type of a struct field referenced by an operand.
static inline Type itemType(const Expression& op0, const Expression& op1) {
    if ( auto st = op0.type().tryAs<type::Struct>() ) {
        if ( auto f = st->field(memberExpression(op1).id().local()) )
            return f->type();
    }

    return type::unknown;
}

} // namespace struct_::detail

BEGIN_OPERATOR_CUSTOM(struct_, Unset)
    Type result(const hilti::node::Range<Expression>& ops) const { return type::void_; }

    bool isLhs() const { return true; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {{{}, type::Struct(type::Wildcard()), false, {}, "struct"},
                                                 {{}, type::Member(type::Wildcard()), false, {}, "<field>"}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node, true);
    }

    std::string doc() const {
        return R"(
Clears an optional field.
)";
    }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM_x(struct_, MemberNonConst, Member)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return type::nonConstant(detail::itemType(ops[0], ops[1]), true);
    }

    bool isLhs() const { return true; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {{{}, type::Struct(type::Wildcard()), false, {}, "struct"},
                                                 {{}, type::Member(type::Wildcard()), false, {}, "<field>"}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Retrieves the value of a struct's field. If the field does not have a value assigned,
it returns its ``&default`` expression if that has been defined; otherwise it
triggers an exception.
)";
    }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM_x(struct_, MemberConst, Member)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return type::constant(detail::itemType(ops[0], ops[1]));
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands =
            {{{}, type::constant(type::Struct(type::Wildcard())), false, {}, "struct"},
             {{}, type::Member(type::Wildcard()), false, {}, "<field>"}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Retrieves the value of a struct's field. If the field does not have a value assigned,
it returns its ``&default`` expression if that has been defined; otherwise it
triggers an exception.
)";
    }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM(struct_, TryMember)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return detail::itemType(ops[0], ops[1]);
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {{{}, type::Struct(type::Wildcard()), false, {}, "struct"},
                                                 {{}, type::Member(type::Wildcard()), false, {}, "<field>"}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Retrieves the value of a struct's field. If the field does not have a value
assigned, it returns its ``&default`` expression if that has been defined;
otherwise it signals a special non-error exception to the host application
(which will normally still lead to aborting execution, similar to the standard
dereference operator, unless the host application specifically handles this
exception differently).
)";
    }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(struct_, HasMember)
    Type result(const hilti::node::Range<Expression>& /* ops */) const { return type::Bool(); }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands =
            {{{}, type::constant(type::Struct(type::Wildcard())), false, {}, "struct"},
             {{}, type::Member(type::Wildcard()), false, {}, "<field>"}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return "Returns true if the struct's field has a value assigned (not counting any ``&default``).";
    }
END_OPERATOR_CUSTOM

OPERATOR_DECLARE_ONLY(struct_, MemberCall)

namespace struct_ {

class MemberCall : public hilti::expression::ResolvedOperatorBase {
public:
    using hilti::expression::ResolvedOperatorBase::ResolvedOperatorBase;

    struct Operator : public hilti::trait::isOperator {
        Operator(const type::Struct& stype, const declaration::Field& f) {
            auto ftype = f.type().as<type::Function>();
            auto op0 = operator_::Operand{{}, stype};
            auto op1 = operator_::Operand{{}, type::Member(f.id())};
            auto op2 = operator_::Operand{{}, type::OperandList::fromParameters(ftype.parameters())};
            _field = f;
            _operands = {op0, op1, op2};
            _result = ftype.result().type();
        };

        static operator_::Kind kind() { return operator_::Kind::MemberCall; }
        const std::vector<operator_::Operand>& operands() const { return _operands; }
        Type result(const hilti::node::Range<Expression>& /* ops */) const { return _result; }
        bool isLhs() const { return false; }
        auto priority() const { return hilti::operator_::Priority::Normal; }
        void validate(const expression::ResolvedOperator& /* i */, operator_::position_t p) const {}
        std::string doc() const { return "<dynamic - no doc>"; }
        std::string docNamespace() const { return "<dynamic - no ns>"; }

        Expression instantiate(const std::vector<Expression>& operands, const Meta& meta) const {
            auto ops =
                std::vector<Expression>{operands[0], expression::Member(_field.id(), _field.type(), _field.meta()),
                                        operands[2]};

            auto ro = expression::ResolvedOperator(MemberCall(*this, ops, meta));
            ro.setMeta(meta);
            return ro;
        }

    private:
        declaration::Field _field;
        std::vector<operator_::Operand> _operands;
        Type _result;
    };
};

} // namespace struct_

} // namespace hilti::operator_
