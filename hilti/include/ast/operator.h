// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <variant>

#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/doc-only.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>
#include <hilti/base/type_erase.h>
#include <hilti/base/visitor-types.h>

namespace hilti {

namespace visitor {}

namespace expression {
namespace resolved_operator {

namespace detail {
class ResolvedOperator;
} // namespace detail
} // namespace resolved_operator

using ResolvedOperator = resolved_operator::detail::ResolvedOperator;

} // namespace expression

namespace trait {
/** Trait for classes implementing the `Operator` interface. */
class isOperator : public isNode {};
} // namespace trait

namespace expression {
class UnresolvedOperator;
} // namespace expression

namespace operator_ {

using position_t = visitor::Position<Node&>;
using const_position_t = visitor::Position<const Node&>;

using OperandType =
    std::variant<Type,
                 std::function<std::optional<Type>(const std::vector<Expression>&, const std::vector<Expression>&)>>;
inline std::optional<Type> type(const OperandType& t, const std::vector<Expression>& orig_ops,
                                const std::vector<Expression>& resolved_ops) {
    if ( const auto& f = std::get_if<
             std::function<std::optional<Type>(const std::vector<Expression>&, const std::vector<Expression>&)>>(&t) )
        return (*f)(orig_ops, resolved_ops);

    return std::get<Type>(t);
}

inline auto operandType(unsigned int op, const char* doc = "<no-doc>") {
    return [=](const std::vector<Expression>& /* orig_ops */,
               const std::vector<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly(doc);

        if ( op >= resolved_ops.size() )
            logger().internalError(util::fmt("operandType(): index %d out of range, only %" PRIu64 " ops available", op,
                                             resolved_ops.size()));

        return resolved_ops[op].type();
    };
}

inline auto elementType(unsigned int op, const char* doc = "<type of element>", bool infer_const = true) {
    return [=](const std::vector<Expression>& /* orig_ops */,
               const std::vector<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly(doc);

        if ( op >= resolved_ops.size() )
            logger().internalError(util::fmt("elementType(): index %d out of range, only %" PRIu64 " ops available", op,
                                             resolved_ops.size()));

        if ( type::isIterable(resolved_ops[op].type()) ) {
            auto t = resolved_ops[op].type().elementType();
            return (infer_const && resolved_ops[op].isConstant()) ? type::constant(t) : std::move(t);
        }

        return {};
    };
}

inline auto constantElementType(unsigned int op, const char* doc = "<type of element>") {
    return [=](const std::vector<Expression>& /* orig_ops */,
               const std::vector<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly(doc);

        if ( op >= resolved_ops.size() )
            logger().internalError(util::fmt("elementType(): index %d out of range, only %" PRIu64 " ops available", op,
                                             resolved_ops.size()));

        if ( type::isIterable(resolved_ops[op].type()) )
            return type::constant(resolved_ops[op].type().elementType());

        return {};
    };
}

inline auto dereferencedType(unsigned int op, const char* doc = "<dereferenced type>", bool infer_const = true) {
    return [=](const std::vector<Expression>& /* orig_ops */,
               const std::vector<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly(doc);

        if ( op >= resolved_ops.size() )
            logger().internalError(util::fmt("dereferencedType(): index %d out of range, only %" PRIu64
                                             " ops available",
                                             op, resolved_ops.size()));

        if ( type::isDereferencable(resolved_ops[op].type()) ) {
            auto t = resolved_ops[op].type().dereferencedType();
            return (infer_const && resolved_ops[op].isConstant()) ? type::constant(t) : std::move(t);
        }

        return {};
    };
}

inline auto sameTypeAs(unsigned int op, const char* doc = "<no-doc>") {
    return [=](const std::vector<Expression>& /* orig_ops */,
               const std::vector<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly(doc);

        if ( op >= resolved_ops.size() )
            logger().internalError(util::fmt("sameTypeAs(): index %d out of range, only %" PRIu64 " ops available", op,
                                             resolved_ops.size()));

        return resolved_ops[op].type();
    };
}

inline auto typedType(unsigned int op, const char* doc = "<type>") {
    return [=](const std::vector<Expression>& /* orig_ops */,
               const std::vector<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly(doc);

        if ( op >= resolved_ops.size() )
            logger().internalError(util::fmt("typedType(): index %d out of range, only %" PRIu64 " ops available", op,
                                             resolved_ops.size()));

        return type::effectiveType(resolved_ops[op].type().as<type::Type_>().typeValue());
    };
}

/** Describes an operand that an operator accepts. */
struct Operand {
    std::optional<ID> id;                    /**< ID for the operand; used only for documentation purposes. */
    OperandType type;                        /**< operand's type */
    bool optional = false;                   /**< true if operand can be skipped; `default_` will be used instead */
    std::optional<Expression> default_ = {}; /**< default valuer if operator is skipped */
    std::optional<std::string> doc;          /**< alternative rendering for the auto-generated documentation */

    bool operator==(const Operand& other) const {
        if ( this == &other )
            return true;

        if ( ! (std::holds_alternative<Type>(type) && std::holds_alternative<Type>(other.type)) )
            return false;

        return std::get<Type>(type) == std::get<Type>(other.type) && id == other.id && optional == other.optional &&
               default_ == other.default_;
    }
};

inline std::ostream& operator<<(std::ostream& out, const Operand& op) {
    if ( auto t = std::get_if<Type>(&op.type) )
        out << *t;
    else
        out << "<inferred type>";

    if ( op.id )
        out << ' ' << *op.id;

    if ( op.default_ )
        out << " = " << *op.default_;
    else if ( op.optional )
        out << " (optional)";

    return out;
}

using ResultType = OperandType;

/**
 * Describes the signature of an operator method.
 *
 * @todo For operands, we only use the type information so far. Instead of
 * using `type::Tuple` to describe the 3rd parameter to a MethodCall
 * operator, we should create a new `type::ArgumentList` that takes a list
 * of `Operand` instances.
 */
struct Signature {
    Type self; /**< type the method operates on */
    bool const_ = true;
    bool lhs = false;          /**< true if operator's result can be assigned to */
    ResultType result;         /**< result of the method; skipped if using `{BEGIN/END}_METHOD_CUSTOM_RESULT}` */
    ID id;                     /**< name of the method */
    std::vector<Operand> args; /**< operands the method receives */
    std::string doc;           /**< documentation string for the autogenerated reference manual */
};

/** Enumeration of all types of operators that HILTI supports. */
enum class Kind {
    Add,
    Begin,
    BitAnd,
    BitOr,
    BitXor,
    Call,
    Cast,
    DecrPostfix,
    DecrPrefix,
    Delete,
    Deref,
    Difference,
    DifferenceAssign,
    Division,
    DivisionAssign,
    Equal,
    End,
    Greater,
    GreaterEqual,
    HasMember,
    In,
    IncrPostfix,
    IncrPrefix,
    Index,
    Lower,
    LowerEqual,
    Member,
    MemberCall,
    Modulo,
    Multiple,
    MultipleAssign,
    Negate,
    New,
    Power,
    ShiftLeft,
    ShiftRight,
    SignNeg,
    SignPos,
    Size,
    Sum,
    SumAssign,
    TryMember,
    Unequal,
    Unknown,
    Unpack
};

/** Returns true for operator types that HILTI considers commutative. */
constexpr auto is_commutative(Kind k) {
    switch ( k ) {
        case Kind::BitAnd:
        case Kind::BitOr:
        case Kind::BitXor:
        case Kind::Equal:
        case Kind::Unequal:
        case Kind::Multiple:
        case Kind::Sum: return true;

        case Kind::Add:
        case Kind::Begin:
        case Kind::Call:
        case Kind::Cast:
        case Kind::DecrPostfix:
        case Kind::DecrPrefix:
        case Kind::Delete:
        case Kind::Deref:
        case Kind::Difference:
        case Kind::DifferenceAssign:
        case Kind::Division:
        case Kind::DivisionAssign:
        case Kind::End:
        case Kind::Greater:
        case Kind::GreaterEqual:
        case Kind::HasMember:
        case Kind::In:
        case Kind::IncrPostfix:
        case Kind::IncrPrefix:
        case Kind::Index:
        case Kind::Lower:
        case Kind::LowerEqual:
        case Kind::Member:
        case Kind::MemberCall:
        case Kind::Modulo:
        case Kind::MultipleAssign:
        case Kind::Negate:
        case Kind::New:
        case Kind::Power:
        case Kind::ShiftLeft:
        case Kind::ShiftRight:
        case Kind::SignNeg:
        case Kind::SignPos:
        case Kind::Size:
        case Kind::SumAssign:
        case Kind::TryMember:
        case Kind::Unknown:
        case Kind::Unpack: return false;
        default: util::cannot_be_reached();
    };
}

namespace detail {
constexpr util::enum_::Value<Kind> kinds[] = {{Kind::Add, "add"},
                                              {Kind::Begin, "begin"},
                                              {Kind::BitAnd, "&"},
                                              {Kind::BitOr, "|"},
                                              {Kind::BitXor, "^"},
                                              {Kind::Call, "call"},
                                              {Kind::Cast, "cast"},
                                              {Kind::DecrPostfix, "--"},
                                              {Kind::DecrPrefix, "--"},
                                              {Kind::Delete, "delete"},
                                              {Kind::Deref, "*"},
                                              {Kind::Division, "/"},
                                              {Kind::DivisionAssign, "/="},
                                              {Kind::Equal, "=="},
                                              {Kind::End, "end"},
                                              {Kind::Greater, ">"},
                                              {Kind::GreaterEqual, ">="},
                                              {Kind::HasMember, "?."},
                                              {Kind::In, "in"},
                                              {Kind::IncrPostfix, "++"},
                                              {Kind::IncrPrefix, "++"},
                                              {Kind::Index, "index"},
                                              {Kind::Lower, "<"},
                                              {Kind::LowerEqual, "<="},
                                              {Kind::Member, "."},
                                              {Kind::MemberCall, "method call"},
                                              {Kind::Negate, "~"},
                                              {Kind::New, "new"},
                                              {Kind::Difference, "-"},
                                              {Kind::DifferenceAssign, "-="},
                                              {Kind::Modulo, "%"},
                                              {Kind::Multiple, "*"},
                                              {Kind::MultipleAssign, "*="},
                                              {Kind::Sum, "+"},
                                              {Kind::SumAssign, "+="},
                                              {Kind::Power, "**"},
                                              {Kind::ShiftLeft, "<<"},
                                              {Kind::ShiftRight, ">>"},
                                              {Kind::SignNeg, "-"},
                                              {Kind::SignPos, "+"},
                                              {Kind::Size, "size"},
                                              {Kind::TryMember, ".?"},
                                              {Kind::Unequal, "!="},
                                              {Kind::Unknown, "<unknown>"},
                                              {Kind::Unpack, "unpack"}};
} // namespace detail

/**
 * Returns a descriptive string representation of an operator kind. This is
 * meant just for display purposes, and does not correspond directly to the
 * HILTI code representation (because thay may differs based on context).
 */
constexpr auto to_string(Kind m) { return util::enum_::to_string(m, detail::kinds); }

namespace detail {
class Operator;

#include <hilti/autogen/__operator.h>

} // namespace detail
} // namespace operator_

using Operator = operator_::detail::Operator;

inline bool operator==(const Operator& x, const Operator& y) {
    if ( &x == &y )
        return true;

    return x.typename_() == y.typename_();
}

} // namespace hilti
