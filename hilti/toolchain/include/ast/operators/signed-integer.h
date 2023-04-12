// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <vector>

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>

namespace hilti::operator_ {

namespace detail {
inline static auto widestTypeSigned() {
    return [=](const hilti::node::Range<Expression>& orig_ops,
               const hilti::node::Range<Expression>& resolved_ops) -> std::optional<Type> {
        if ( orig_ops.empty() && resolved_ops.empty() )
            return type::DocOnly("int<*>");

        int w1 = 0;
        int w2 = 0;

        if ( auto t = orig_ops[0].type().tryAs<type::SignedInteger>() )
            w1 = t->width();
        else if ( auto t = orig_ops[0].type().tryAs<type::UnsignedInteger>() )
            w1 = t->width();

        if ( auto t = orig_ops[1].type().tryAs<type::SignedInteger>() )
            w2 = t->width();
        else if ( auto t = orig_ops[1].type().tryAs<type::UnsignedInteger>() )
            w2 = t->width();

        if ( ! (w1 && w2) )
            return {};

        const bool is_ctor1 = orig_ops[0].isA<expression::Ctor>();
        const bool is_ctor2 = orig_ops[1].isA<expression::Ctor>();

        if ( is_ctor1 && ! is_ctor2 )
            return type::SignedInteger(w2);

        if ( is_ctor2 && ! is_ctor1 )
            return type::SignedInteger(w1);

        return type::SignedInteger(std::max(w1, w2));
    };
}
} // namespace detail

STANDARD_OPERATOR_1(signed_integer, DecrPostfix, operator_::sameTypeAs(0, "int"), type::SignedInteger(type::Wildcard()),
                    "Decrements the value, returning the old value.");
STANDARD_OPERATOR_1(signed_integer, DecrPrefix, operator_::sameTypeAs(0, "int"), type::SignedInteger(type::Wildcard()),
                    "Increments the value, returning the new value.");
STANDARD_OPERATOR_1(signed_integer, IncrPostfix, operator_::sameTypeAs(0, "int"), type::SignedInteger(type::Wildcard()),
                    "Increments the value, returning the old value.");
STANDARD_OPERATOR_1(signed_integer, IncrPrefix, operator_::sameTypeAs(0, "int"), type::SignedInteger(type::Wildcard()),
                    "Increments the value, returning the new value.");
STANDARD_OPERATOR_1(signed_integer, SignNeg, operator_::sameTypeAs(0, "int"), type::SignedInteger(type::Wildcard()),
                    "Inverts the sign of the integer.");
STANDARD_OPERATOR_2(signed_integer, Difference, detail::widestTypeSigned(), detail::widestTypeSigned(),
                    detail::widestTypeSigned(), "Computes the difference between the two integers.");
STANDARD_OPERATOR_2(signed_integer, DifferenceAssign, operator_::sameTypeAs(0, "int"),
                    type::SignedInteger(type::Wildcard()), operator_::sameTypeAs(0, "int"),
                    "Decrements the first value by the second, assigning the new value.");
STANDARD_OPERATOR_2(signed_integer, Division, detail::widestTypeSigned(), detail::widestTypeSigned(),
                    detail::widestTypeSigned(), "Divides the first integer by the second.");
STANDARD_OPERATOR_2(signed_integer, DivisionAssign, operator_::sameTypeAs(0, "int"),
                    type::SignedInteger(type::Wildcard()), operator_::sameTypeAs(0, "int"),
                    "Divides the first value by the second, assigning the new value.");
STANDARD_OPERATOR_2(signed_integer, Equal, type::Bool(), detail::widestTypeSigned(), detail::widestTypeSigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2(signed_integer, Greater, type::Bool(), detail::widestTypeSigned(), detail::widestTypeSigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2(signed_integer, GreaterEqual, type::Bool(), detail::widestTypeSigned(), detail::widestTypeSigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2(signed_integer, Lower, type::Bool(), detail::widestTypeSigned(), detail::widestTypeSigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2(signed_integer, LowerEqual, type::Bool(), detail::widestTypeSigned(), detail::widestTypeSigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2(signed_integer, Modulo, detail::widestTypeSigned(), detail::widestTypeSigned(),
                    detail::widestTypeSigned(), "Computes the modulus of the first integer divided by the second.");
STANDARD_OPERATOR_2(signed_integer, Multiple, detail::widestTypeSigned(), detail::widestTypeSigned(),
                    detail::widestTypeSigned(), "Multiplies the first integer by the second.");
STANDARD_OPERATOR_2(signed_integer, MultipleAssign, operator_::sameTypeAs(0, "int"),
                    type::SignedInteger(type::Wildcard()), operator_::sameTypeAs(0, "int"),
                    "Multiplies the first value by the second, assigning the new value.");
STANDARD_OPERATOR_2(signed_integer, Power, detail::widestTypeSigned(), detail::widestTypeSigned(),
                    detail::widestTypeSigned(), "Computes the first integer raised to the power of the second.");
STANDARD_OPERATOR_2(signed_integer, Sum, detail::widestTypeSigned(), detail::widestTypeSigned(),
                    detail::widestTypeSigned(), "Computes the sum of the integers.");
STANDARD_OPERATOR_2(signed_integer, SumAssign, operator_::sameTypeAs(0, "int"), type::SignedInteger(type::Wildcard()),
                    operator_::sameTypeAs(0, "int"), "Increments the first integer by the second.");
STANDARD_OPERATOR_2(signed_integer, Unequal, type::Bool(), detail::widestTypeSigned(), detail::widestTypeSigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2x(signed_integer, CastToSigned, Cast, operator_::typedType(1, "int<*>"),
                     type::SignedInteger(type::Wildcard()), type::Type_(type::SignedInteger(type::Wildcard())),
                     "Converts the value into another signed integer type, accepting any loss of information.");
STANDARD_OPERATOR_2x(signed_integer, CastToUnsigned, Cast, operator_::typedType(1, "uint<*>"),
                     type::SignedInteger(type::Wildcard()), type::Type_(type::UnsignedInteger(type::Wildcard())),
                     "Converts the value into an unsigned integer type, accepting any loss of information.");
STANDARD_OPERATOR_2x(signed_integer, CastToReal, Cast, type::Real(), type::SignedInteger(type::Wildcard()),
                     type::Type_(type::Real()), "Converts the value into a real, accepting any loss of information.");
STANDARD_OPERATOR_2x(signed_integer, CastToEnum, Cast, operator_::typedType(1, "enum<*>"),
                     type::SignedInteger(type::Wildcard()), type::Type_(type::Enum(type::Wildcard())),
                     "Converts the value into an enum instance. The value does *not* need to correspond to "
                     "any of the target type's enumerator labels.");
STANDARD_OPERATOR_2x(signed_integer, CastToInterval, Cast, type::Interval(), type::SignedInteger(type::Wildcard()),
                     type::Type_(type::Interval()), "Interprets the value as number of seconds.");
STANDARD_OPERATOR_2x(signed_integer, CastToBool, Cast, type::Bool(), type::SignedInteger(type::Wildcard()),
                     type::Type_(type::Bool()), "Converts the value to a boolean by comparing against zero");

STANDARD_KEYWORD_CTOR(signed_integer, CtorSigned8, "int8", type::SignedInteger(8),
                      type::SignedInteger(type::Wildcard()), "Creates a 8-bit signed integer value.");
STANDARD_KEYWORD_CTOR(signed_integer, CtorSigned16, "int16", type::SignedInteger(16),
                      type::SignedInteger(type::Wildcard()), "Creates a 16-bit signed integer value.");
STANDARD_KEYWORD_CTOR(signed_integer, CtorSigned32, "int32", type::SignedInteger(32),
                      type::SignedInteger(type::Wildcard()), "Creates a 32-bit signed integer value.");
STANDARD_KEYWORD_CTOR(signed_integer, CtorSigned64, "int64", type::SignedInteger(64),
                      type::SignedInteger(type::Wildcard()), "Creates a 64-bit signed integer value.");
STANDARD_KEYWORD_CTOR(signed_integer, CtorUnsigned8, "int8", type::SignedInteger(8),
                      type::UnsignedInteger(type::Wildcard()), "Creates a 8-bit signed integer value.");
STANDARD_KEYWORD_CTOR(signed_integer, CtorUnsigned16, "int16", type::SignedInteger(16),
                      type::UnsignedInteger(type::Wildcard()), "Creates a 16-bit signed integer value.");
STANDARD_KEYWORD_CTOR(signed_integer, CtorUnsigned32, "int32", type::SignedInteger(32),
                      type::UnsignedInteger(type::Wildcard()), "Creates a 32-bit signed integer value.");
STANDARD_KEYWORD_CTOR(signed_integer, CtorUnsigned64, "int64", type::SignedInteger(64),
                      type::UnsignedInteger(type::Wildcard()), "Creates a 64-bit signed integer value.");

} // namespace hilti::operator_
