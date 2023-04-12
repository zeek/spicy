// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/unknown.h>

#include <spicy/ast/types/bitfield.h>

namespace spicy::operator_ {

namespace bitfield::detail {

// Returns an operand as a member expression.
static hilti::expression::Member memberExpression(const Expression& op) {
    if ( auto c = op.tryAs<hilti::expression::Coerced>() )
        return c->expression().as<hilti::expression::Member>();

    return op.as<hilti::expression::Member>();
}

// Checks if an operand refers to a valid field inside a bitfield.
static inline void checkName(const Expression& op0, const Expression& op1, Node& n) {
    auto id = memberExpression(op1).id().local();

    if ( const auto& f = op0.type().as<type::Bitfield>().bits(id); ! f )
        n.addError(hilti::util::fmt("bitfield type does not have attribute '%s'", id));
}

static inline Type itemType(const Expression& op0, const Expression& op1) {
    if ( auto st = op0.type().tryAs<type::Bitfield>() ) {
        if ( const auto& f = st->bits(memberExpression(op1).id().local()) )
            return f->itemType();
    }

    return type::unknown;
}

} // namespace bitfield::detail

BEGIN_OPERATOR_CUSTOM(bitfield, Member)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return detail::itemType(ops[0], ops[1]);
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<hilti::operator_::Operand>& operands() const {
        static std::vector<hilti::operator_::Operand> _operands =
            {{{}, type::constant(type::Bitfield(type::Wildcard())), false, {}, "bitfield"},
             {{}, type::Member(type::Wildcard()), false, {}, "<attribute>"}};
        return _operands;
    }

    void validate(const hilti::expression::ResolvedOperator& i, hilti::operator_::position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Retrieves the value of a bitfield's attribute. This is the value of the
corresponding bits inside the underlying integer value, shifted to the very
right.
)";
    }
END_OPERATOR_CUSTOM_x

} // namespace spicy::operator_
