// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/ctors/all.h>
#include <hilti/ast/expressions/all.h>
#include <hilti/ast/types/id.h>

namespace hilti::builder {

// ID expression

inline Expression id(ID id_, Meta m = Meta()) { return expression::UnresolvedID(std::move(id_), std::move(m)); }

// Ctor expressions

inline Expression string(std::string s, const Meta& m = Meta()) {
    return expression::Ctor(ctor::String(std::move(s), m), m);
}

inline Expression bool_(bool b, const Meta& m = Meta()) { return expression::Ctor(ctor::Bool(b, m), m); }

inline Expression bytes(std::string s, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Bytes(std::move(s), m), m);
}

inline Expression coerceTo(Expression e, Type t, const Meta& m) {
    return expression::PendingCoerced(std::move(e), std::move(t), m);
}

inline Expression coerceTo(const Expression& e, Type t) {
    return expression::PendingCoerced(e, std::move(t), e.meta());
}

inline Expression default_(Type t, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Default(std::move(t), m), m);
}

inline Expression default_(Type t, std::vector<Expression> type_args, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Default(std::move(t), std::move(type_args), m), m);
}

inline Expression exception(Type t, std::string msg, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Exception(std::move(t), builder::string(std::move(msg)), m), m);
}

inline Expression exception(Type t, Expression msg, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Exception(std::move(t), std::move(msg), m), m);
}

inline Expression integer(int i, const Meta& m = Meta()) {
    return expression::Ctor(ctor::SignedInteger(static_cast<int64_t>(i), 64, m), m);
}

inline Expression integer(int64_t i, const Meta& m = Meta()) {
    return expression::Ctor(ctor::SignedInteger(i, 64, m), m);
}

inline Expression integer(unsigned int i, const Meta& m = Meta()) {
    return expression::Ctor(ctor::UnsignedInteger(i, 64, m), m);
}

inline Expression integer(uint64_t i, const Meta& m = Meta()) {
    return expression::Ctor(ctor::UnsignedInteger(i, 64, m), m);
}

inline Expression null(const Meta& m = Meta()) { return expression::Ctor(ctor::Null(m), m); }

inline Expression optional(Expression e, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Optional(std::move(e), m), m);
}

inline Expression optional(Type t, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Optional(std::move(t), m), m);
}

inline Expression port(hilti::ctor::Port::Value p, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Port(p, m), m);
}

inline Expression regexp(std::string p, std::optional<AttributeSet> attrs = {}, const Meta& m = Meta()) {
    return expression::Ctor(ctor::RegExp({std::move(p)}, std::move(attrs), m), m);
}

inline Expression regexp(std::vector<std::string> p, std::optional<AttributeSet> attrs = {}, const Meta& m = Meta()) {
    return expression::Ctor(ctor::RegExp(std::move(p), std::move(attrs), m), m);
}

inline Expression stream(std::string s, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Stream(std::move(s), m), m);
}

inline Expression struct_(std::vector<ctor::struct_::Field> f, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Struct(std::move(f), m), m);
}

inline Expression struct_(std::vector<ctor::struct_::Field> f, Type t, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Struct(std::move(f), std::move(t), m), m);
}

inline Expression tuple(std::vector<Expression> v, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Tuple(std::move(v), m), m);
}

inline Expression vector(const std::vector<Expression>& v, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Vector(v, m), m);
}

inline Expression vector(Type t, std::vector<Expression> v, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Vector(std::move(t), std::move(v), m), m);
}

inline Expression vector(Type t, const Meta& m = Meta()) {
    return expression::Ctor(ctor::Vector(std::move(t), {}, m), m);
}

inline Expression void_(const Meta& m = Meta()) { return expression::Void(m); }

inline Expression strong_reference(Type t, const Meta& m = Meta()) {
    return expression::Ctor(ctor::StrongReference(std::move(t), m), m);
}

inline Expression weak_reference(Type t, const Meta& m = Meta()) {
    return expression::Ctor(ctor::WeakReference(std::move(t), m), m);
}

inline Expression value_reference(Expression e, const Meta& m = Meta()) {
    return expression::Ctor(ctor::ValueReference(std::move(e), m), m);
}

// Operator expressions

inline Expression and_(Expression op0, Expression op1, const Meta& m = Meta()) {
    return expression::LogicalAnd(std::move(op0), std::move(op1), m);
}

inline Expression or_(Expression op0, Expression op1, const Meta& m = Meta()) {
    return expression::LogicalOr(std::move(op0), std::move(op1), m);
}

inline Expression begin(Expression e, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Begin, {std::move(e)}, m);
}

inline Expression cast(Expression e, Type dst, Meta m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Cast, {std::move(e), expression::Type_(std::move(dst))},
                                          std::move(m));
}

inline Expression delete_(Expression self, ID field, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Delete,
                                          {std::move(self), expression::Member(std::move(field))}, m);
}

inline Expression deref(Expression e, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Deref, {std::move(e)}, m);
}

inline Expression end(Expression e, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::End, {std::move(e)}, m);
}

inline Expression call(ID id_, std::vector<Expression> v, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Call, {id(std::move(id_), m), tuple(std::move(v), m)}, m);
}

inline Expression index(Expression value, unsigned int index, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Index, {std::move(value), integer(index, m)}, m);
}

inline Expression size(Expression op, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Size, {std::move(op)}, m);
}

inline Expression modulo(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Modulo, {std::move(op1), std::move(op2)}, m);
}

inline Expression lowerEqual(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::LowerEqual, {std::move(op1), std::move(op2)}, m);
}

inline Expression greaterEqual(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::GreaterEqual, {std::move(op1), std::move(op2)}, m);
}

inline Expression lower(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Lower, {std::move(op1), std::move(op2)}, m);
}

inline Expression greater(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Greater, {std::move(op1), std::move(op2)}, m);
}

inline Expression equal(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Equal, {std::move(op1), std::move(op2)}, m);
}

inline Expression unequal(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Unequal, {std::move(op1), std::move(op2)}, m);
}

inline Expression member(Expression self, std::string id_, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Member,
                                          {std::move(self), expression::Member(ID(std::move(id_)), m)}, m);
}

inline Expression memberCall(Expression self, std::string id_, std::vector<Expression> v, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::MemberCall,
                                          {std::move(self), expression::Member(ID(std::move(id_)), m),
                                           tuple(std::move(v), m)},
                                          m);
}

inline Expression unpack(Type type, std::vector<Expression> args, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Unpack,
                                          {hilti::expression::Type_(std::move(type), m), tuple(std::move(args), m)}, m);
}

inline Expression unset(Expression self, ID field, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Unset,
                                          {std::move(self), expression::Member(std::move(field))}, m);
}

inline Expression sumAssign(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::SumAssign, {std::move(op1), std::move(op2)}, m);
}

inline Expression deferred(Expression e, Meta m = Meta()) { return expression::Deferred(std::move(e), std::move(m)); }

inline Expression differenceAssign(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::DifferenceAssign, {std::move(op1), std::move(op2)}, m);
}

inline Expression sum(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Sum, {std::move(op1), std::move(op2)}, m);
}

inline Expression difference(Expression op1, Expression op2, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::Difference, {std::move(op1), std::move(op2)}, m);
}

inline Expression decrementPostfix(Expression op, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::DecrPostfix, {std::move(op)}, m);
}

inline Expression decrementPrefix(Expression op, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::DecrPrefix, {std::move(op)}, m);
}

inline Expression incrementPostfix(Expression op, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::IncrPostfix, {std::move(op)}, m);
}

inline Expression incrementPrefix(Expression op, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::IncrPrefix, {std::move(op)}, m);
}

inline Expression new_(Type t, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::New,
                                          {expression::Type_(std::move(t), m),
                                           hilti::expression::Ctor(hilti::ctor::Tuple({}, m))},
                                          m);
}

inline Expression new_(Type t, std::vector<Expression> args, const Meta& m = Meta()) {
    return expression::UnresolvedOperator(operator_::Kind::New,
                                          {expression::Type_(std::move(t), m),
                                           hilti::expression::Ctor(hilti::ctor::Tuple(std::move(args), m))},
                                          m);
}

// Other expressions

inline Expression expression(Ctor c, Meta m = Meta()) { return expression::Ctor(std::move(c), std::move(m)); }

inline Expression expression(const Location& l) { return expression::Ctor(ctor::String(l), l); }

inline Expression expression(const Meta& m) { return expression::Ctor(ctor::String(m.location()), m); }

inline Expression move(Expression e, Meta m = Meta()) { return expression::Move(std::move(e), std::move(m)); }

inline Expression typeinfo(Type t, Meta m = Meta()) { return expression::TypeInfo(std::move(t), std::move(m)); }

inline Expression self(NodeRef d, Meta m = Meta()) {
    return expression::Keyword(hilti::expression::keyword::Kind::Self, std::move(d), std::move(m));
}

inline Expression dollardollar(Meta m = Meta()) {
    return expression::Keyword(hilti::expression::keyword::Kind::DollarDollar, std::move(m));
}

inline Expression dollardollar(Type t, Meta m = Meta()) {
    return expression::Keyword(hilti::expression::keyword::Kind::DollarDollar, std::move(t), std::move(m));
}

inline Expression assign(Expression target, Expression src, Meta m = Meta()) {
    return expression::Assign(std::move(target), std::move(src), std::move(m));
}

inline Expression not_(Expression e, Meta m = Meta()) { return expression::LogicalNot(std::move(e), std::move(m)); }

inline Expression ternary(Expression cond, Expression true_, Expression false_, Meta m = Meta()) {
    return expression::Ternary(std::move(cond), std::move(true_), std::move(false_), std::move(m));
}

inline Expression min(const Expression& e1, const Expression& e2, const Meta& m = Meta()) {
    return ternary(lowerEqual(e1, e2, m), e1, e2, m);
}

inline Expression max(const Expression& e1, const Expression& e2, const Meta& m = Meta()) {
    return ternary(lowerEqual(e1, e2, m), e2, e1, m);
}

inline Expression type_wrapped(Expression e, const Meta& m = Meta()) {
    return expression::TypeWrapped(std::move(e), m);
}

inline Expression type_wrapped(Expression e, Type t, const Meta& m = Meta()) {
    return expression::TypeWrapped(std::move(e), std::move(t), m);
}

inline Expression expect_type(Expression e, Type expected, const Meta& m = Meta()) {
    return expression::TypeWrapped(e, std::move(expected), expression::TypeWrapped::ValidateTypeMatch(),
                                   m ? std::move(m) : e.meta());
}

// Forces interpreting a given expression as a value of a __library_type.
inline Expression library_type_value(Expression e, ID library_type, const Meta& m = Meta()) {
    return expression::TypeWrapped(e, hilti::type::UnresolvedID(std::move(library_type), m), m);
}

} // namespace hilti::builder
