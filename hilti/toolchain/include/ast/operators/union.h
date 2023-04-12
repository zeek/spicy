// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expressions/member.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/union.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::operator_ {

namespace union_::detail {

// Returns an operand as a member expression.
static expression::Member memberExpression(const Expression& op) {
    if ( auto c = op.tryAs<expression::Coerced>() )
        return c->expression().as<expression::Member>();

    return op.as<expression::Member>();
}

// Checks if an operand refers to a valid field inside a union.
static inline void checkName(const Expression& op0, const Expression& op1, Node& n) {
    auto id = memberExpression(op1).id().local();

    if ( auto f = op0.type().as<type::Union>().field(id); ! f )
        n.addError(util::fmt("type does not have field '%s'", id));
}

// Returns the type of a union field referenced by an operand.
static inline Type itemType(const Expression& op0, const Expression& op1) {
    if ( auto st = op0.type().tryAs<type::Union>() ) {
        if ( auto f = st->field(memberExpression(op1).id().local()) )
            return f->type();
    }

    return type::unknown;
}

// Returns the result type of a union method referenced by an operand.
static inline Type methodResult(const Expression& /* op0 */, const Expression& op1) {
    if ( auto f = memberExpression(op1).type().template tryAs<type::Function>() )
        return f->result().type();

    return type::unknown;
}

} // namespace union_::detail

STANDARD_OPERATOR_2(union_, Equal, type::Bool(), type::constant(type::Union(type::Wildcard())),
                    operator_::sameTypeAs(0, "union<*>"), "Compares two unions element-wise.");
STANDARD_OPERATOR_2(union_, Unequal, type::Bool(), type::constant(type::Union(type::Wildcard())),
                    operator_::sameTypeAs(0, "union<*>"), "Compares two unions element-wise.");

BEGIN_OPERATOR_CUSTOM_x(union_, MemberConst, Member)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return detail::itemType(ops[0], ops[1]);
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands =
            {{{}, type::constant(type::Union(type::Wildcard())), false, {}, "union"},
             {{}, type::Member(type::Wildcard()), false, {}, "<field>"}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Retrieves the value of a union's field. If the union does not have the field set,
this triggers an exception.
)";
    }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM_x(union_, MemberNonConst, Member)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return detail::itemType(ops[0], ops[1]);
    }

    bool isLhs() const { return true; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {{{}, type::Union(type::Wildcard()), false, {}, "union"},
                                                 {{}, type::Member(type::Wildcard()), false, {}, "<field>"}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Retrieves the value of a union's field. If the union does not have the field set,
this triggers an exception unless the value is only being assigned to.
)";
    }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM(union_, HasMember)
    Type result(const hilti::node::Range<Expression>& /* ops */) const { return type::Bool(); }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {{{}, type::Union(type::Wildcard()), false, {}, "union"},
                                                 {{}, type::Member(type::Wildcard()), false, {}, "<field>"}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const { return "Returns true if the union's field is set."; }
END_OPERATOR_CUSTOM

} // namespace hilti::operator_
