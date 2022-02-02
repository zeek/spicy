// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
//
// This code adapts a number of operators from HILTI's struct type to Spicy's unit type.

#pragma once

#include <string>
#include <vector>

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/unknown.h>

#include <spicy/ast/types/unit.h>

using namespace ::hilti::operator_;

namespace spicy::operator_ {

namespace unit::detail {

// Returns an operand as a member expression.
static hilti::expression::Member memberExpression(const Expression& op) {
    if ( auto c = op.tryAs<hilti::expression::Coerced>() )
        return c->expression().as<hilti::expression::Member>();

    return op.as<hilti::expression::Member>();
}

// Checks if an operand refers to a valid field inside a unit.
static inline void checkName(const Expression& op0, const Expression& op1, Node& node) {
    auto id = memberExpression(op1).id().local();
    auto i = op0.type().as<type::Unit>().itemByName(id);

    if ( ! i )
        node.addError(hilti::util::fmt("type does not have field '%s'", id));
}

// Returns the type of a unit field referenced by an operand.
static inline Type itemType(const Expression& op0, const Expression& op1) {
    if ( auto st = op0.type().tryAs<type::Unit>() ) {
        if ( auto i = st->itemByName(memberExpression(op1).id().local()) )
            return i->itemType();
    }

    return type::unknown;
}

} // namespace unit::detail

BEGIN_OPERATOR_CUSTOM(unit, Unset)
    Type result(const hilti::node::Range<Expression>& ops) const { return type::void_; }

    bool isLhs() const { return true; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    std::vector<Operand> operands() const {
        return {{.type = type::Unit(type::Wildcard()), .doc = "unit"},
                {.type = type::Member(type::Wildcard()), .doc = "<field>"}};
    }

    void validate(const hilti::expression::ResolvedOperator& i, hilti::operator_::position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Clears an optional field.
)";
    }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM_x(unit, MemberNonConst, Member)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return detail::itemType(ops[0], ops[1]);
    }

    bool isLhs() const { return true; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    std::vector<Operand> operands() const {
        return {{.type = type::Unit(type::Wildcard()), .doc = "unit"},
                {.type = type::Member(type::Wildcard()), .doc = "<field>"}};
    }

    void validate(const hilti::expression::ResolvedOperator& i, hilti::operator_::position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);

        if ( i.op0().isConstant() )
            p.node.addError("cannot assign to field of constant unit instance");
    }

    std::string doc() const {
        return R"(
Retrieves the value of a unit's field. If the field does not have a value assigned,
it returns its ``&default`` expression if that has been defined; otherwise it
triggers an exception.
)";
    }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM_x(unit, MemberConst, Member)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return detail::itemType(ops[0], ops[1]);
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    std::vector<Operand> operands() const {
        return {{.type = type::constant(type::Unit(type::Wildcard())), .doc = "unit"},
                {.type = type::Member(type::Wildcard()), .doc = "<field>"}};
    }

    void validate(const hilti::expression::ResolvedOperator& i, position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Retrieves the value of a unit's field. If the field does not have a value assigned,
it returns its ``&default`` expression if that has been defined; otherwise it
triggers an exception.
)";
    }
END_OPERATOR_CUSTOM_x

BEGIN_OPERATOR_CUSTOM(unit, TryMember)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<field type>");

        return detail::itemType(ops[0], ops[1]);
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    std::vector<Operand> operands() const {
        return {{.type = type::Unit(type::Wildcard()), .doc = "unit"},
                {.type = type::Member(type::Wildcard()), .doc = "<field>"}};
    }

    void validate(const hilti::expression::ResolvedOperator& i, position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return R"(
Retrieves the value of a unit's field. If the field does not have a value
assigned, it returns its ``&default`` expression if that has been defined;
otherwise it signals a special non-error exception to the host application
(which will normally still lead to aborting execution, similar to the standard
dereference operator, unless the host application specifically handles this
exception differently).
)";
    }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(unit, HasMember)
    Type result(const hilti::node::Range<Expression>& /* ops */) const { return type::Bool(); }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    std::vector<Operand> operands() const {
        return {{.type = type::constant(type::Unit(type::Wildcard())), .doc = "unit"},
                {.type = type::Member(type::Wildcard()), .doc = "<field>"}};
    }

    void validate(const hilti::expression::ResolvedOperator& i, position_t p) const {
        detail::checkName(i.op0(), i.op1(), p.node);
    }

    std::string doc() const {
        return "Returns true if the unit's field has a value assigned (not counting any ``&default``).";
    }
END_OPERATOR_CUSTOM

OPERATOR_DECLARE_ONLY(unit, MemberCall)

namespace unit {

class MemberCall : public hilti::expression::ResolvedOperatorBase {
public:
    using hilti::expression::ResolvedOperatorBase::ResolvedOperatorBase;

    struct Operator : public hilti::trait::isOperator {
        Operator(const type::Unit& stype, const type::unit::item::Field& f) : _field(f) {
            auto ftype = f.itemType().as<type::Function>();
            auto op0 = Operand{.type = stype};
            auto op1 = Operand{.type = type::Member(f.id())};
            auto op2 = Operand{.type = type::OperandList::fromParameters(ftype.parameters())};
            _operands = {op0, op1, op2};
            _result = ftype.result().type();
        };

        static Kind kind() { return Kind::MemberCall; }
        std::vector<Operand> operands() const { return _operands; }
        Type result(const hilti::node::Range<Expression>& /* ops */) const { return _result; }
        bool isLhs() const { return false; }
        auto priority() const { return hilti::operator_::Priority::Normal; }
        void validate(const hilti::expression::ResolvedOperator& /* i */, position_t p) const {}
        std::string doc() const { return "<dynamic - no doc>"; }
        std::string docNamespace() const { return "<dynamic - no ns>"; }

        Expression instantiate(const std::vector<Expression>& operands, const Meta& meta) const {
            auto ops = std::vector<Expression>{operands[0],
                                               hilti::expression::Member(_field.id(), _field.itemType(), _field.meta()),
                                               operands[2]};

            auto ro = hilti::expression::ResolvedOperator(MemberCall(*this, ops, meta));
            ro.setMeta(meta);
            return ro;
        }

    private:
        type::unit::item::Field _field;
        std::vector<Operand> _operands;
        Type _result;
    };
};

} // namespace unit

BEGIN_METHOD(unit, Offset)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::UnsignedInteger(64),
                                           .id = "offset",
                                           .args = {},
                                           .doc = R"(
Returns the offset of the current location in the input stream relative to the
unit's start. If executed from inside a field hook, the offset will represent
the first byte that the field has been parsed from. If this method is called
before the unit's parsing has begun, it will throw a runtime exception. Once
parsing has started, the offset will remain available for the unit's entire
life time.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Position)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::stream::Iterator(),
                                           .id = "position",
                                           .args = {},
                                           .doc = R"(
Returns an iterator to the current position in the unit's input stream. If
executed from inside a field hook, the position will represent the first byte
that the field has been parsed from. If this method is called before the unit's
parsing has begun, it will throw a runtime exception.
)"};
    }
END_METHOD


BEGIN_METHOD(unit, Input)
    auto signature() const {
        return hilti::operator_::Signature{.self = type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::stream::Iterator(),
                                           .id = "input",
                                           .args = {},
                                           .doc = R"(
Returns an iterator referring to the input location where the current unit has
begun parsing. If this method is called before the units parsing has begun, it
will throw a runtime exception. Once available, the input position will remain
accessible for the unit's entire life time.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, SetInput)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::void_,
                                           .id = "set_input",
                                           .args = {{.id = "i",
                                                     .type = type::constant(hilti::type::stream::Iterator())}},
                                           .doc = R"(
Moves the current parsing position to *i*. The iterator *i* must be into the
input of the current unit, or the method will throw a runtime exception.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Find)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::Optional(hilti::type::stream::Iterator()),
                                           .id = "find",
                                           .args =
                                               {
                                                   {.id = "needle", .type = type::constant(hilti::type::Bytes())},
                                                   {.id = "dir",
                                                    .type = type::constant(hilti::type::Enum(type::Wildcard())),
                                                    .optional = true},
                                                   {.id = "start",
                                                    .type = type::constant(hilti::type::stream::Iterator()),
                                                    .optional = true},

                                               },
                                           .doc = R"(
Searches a *needle* pattern inside the input region defined by where the unit
began parsing and its current parsing position. If executed from inside a field
hook, the current parasing position will represent the *first* byte that the
field has been parsed from. By default, the search will start at the beginning
of that region and scan forward. If the direction is
``spicy::Direcction::Backward``, the search will start at the end of the region
and scan backward. In either case, a starting position can also be explicitly
given, but must lie inside the same region.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, ConnectFilter)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::void_,
                                           .id = "connect_filter",
                                           .args = {{.id = "filter",
                                                     .type = hilti::type::StrongReference(
                                                         spicy::type::Unit(type::Wildcard()))}},
                                           .doc = R"(
Connects a separate filter unit to transform the unit's input transparently
before parsing. The filter unit will see the original input, and this unit will
receive everything the filter passes on through ``forward()``.

Filters can be connected only before a unit's parsing begins. The latest
possible point is from inside the target unit's ``%init`` hook.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Forward)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::void_,
                                           .id = "forward",
                                           .args = {{.id = "data", .type = hilti::type::Bytes()}},
                                           .doc = R"(
If the unit is connected as a filter to another one, this method forwards
transformed input over to that other one to parse. If the unit is not connected,
this method will silently discard the data.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, ForwardEod)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::void_,
                                           .id = "forward_eod",
                                           .args = {},
                                           .doc = R"(
If the unit is connected as a filter to another one, this method signals that
other one that end of its input has been reached. If the unit is not connected,
this method will not do anything.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Backtrack)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::void_,
                                           .id = "backtrack",
                                           .args = {},
                                           .doc = R"(
Aborts parsing at the current position and returns back to the most recent
``&try`` attribute. Turns into a parse error if there's no ``&try`` in scope.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Confirm)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::void_,
                                           .id = "confirm",
                                           .args = {},
                                           .doc = R"(
For a unit it trial mode confirm that the unit is successfully synchronized to
the input; the unit is then put into regular parsing mode again. If the unit is
not in trial mode ``confirm`` has no effect.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Reject)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::void_,
                                           .id = "reject",
                                           .args = {},
                                           .doc = R"(
Reject a unit in trial mode; this immediately fails parsing of the unit and raises
the parse error which caused the unit to be put into trial mode. If the unit is
not in trial mode this triggers a generic parse error.
)"};
    }
END_METHOD

static inline auto contextResult(bool is_const) {
    return [=](const hilti::node::Range<Expression>& /* orig_ops */,
               const hilti::node::Range<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly("<context>&");

        const auto& ctype = resolved_ops[0].type().as<type::Unit>().contextType();
        assert(ctype);
        return Type(type::StrongReference(*ctype));
    };
}

BEGIN_METHOD(unit, ContextConst)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = contextResult(true),
                                           .id = "context",
                                           .args = {},
                                           .doc = R"(
Returns a reference to the ``%context`` instance associated with the unit.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, ContextNonConst)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Unit(type::Wildcard()),
                                           .result = contextResult(false),
                                           .id = "context",
                                           .args = {},
                                           .doc = R"(
Returns a reference to the ``%context`` instance associated with the unit.
)"};
    }
END_METHOD

} // namespace spicy::operator_
