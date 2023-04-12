// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <vector>

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/string.h>

namespace hilti::operator_ {

namespace detail {
inline static auto widestTypeUnsigned() {
    return [=](const hilti::node::Range<Expression>& orig_ops,
               const hilti::node::Range<Expression>& resolved_ops) -> std::optional<Type> {
        if ( orig_ops.empty() && resolved_ops.empty() )
            return type::DocOnly("uint<*>");

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
            return type::UnsignedInteger(w2);

        if ( is_ctor2 && ! is_ctor1 )
            return type::UnsignedInteger(w1);

        return type::UnsignedInteger(std::max(w1, w2));
    };
}

inline static auto sameWidthSigned() {
    return [=](const hilti::node::Range<Expression>& orig_ops,
               const hilti::node::Range<Expression>& resolved_ops) -> std::optional<Type> {
        if ( orig_ops.empty() && resolved_ops.empty() )
            return type::DocOnly("int<*>");

        if ( auto t = orig_ops[0].type().tryAs<type::UnsignedInteger>() )
            return type::SignedInteger(t->width());
        else
            return {};
    };
}

} // namespace detail

STANDARD_OPERATOR_1(unsigned_integer, DecrPostfix, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), "Decrements the value, returning the old value.");
STANDARD_OPERATOR_1(unsigned_integer, DecrPrefix, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), "Increments the value, returning the new value.");
STANDARD_OPERATOR_1(unsigned_integer, IncrPostfix, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), "Increments the value, returning the old value.");
STANDARD_OPERATOR_1(unsigned_integer, IncrPrefix, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), "Increments the value, returning the new value.");
STANDARD_OPERATOR_1(unsigned_integer, SignNeg, detail::sameWidthSigned(), type::UnsignedInteger(type::Wildcard()),
                    "Inverts the sign of the integer.");
STANDARD_OPERATOR_1(unsigned_integer, Negate, operator_::sameTypeAs(0, "uint"), type::UnsignedInteger(type::Wildcard()),
                    "Computes the bit-wise negation of the integer.");
STANDARD_OPERATOR_2(unsigned_integer, BitAnd, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Computes the bit-wise 'and' of the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, BitOr, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Computes the bit-wise 'or' of the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, BitXor, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Computes the bit-wise 'xor' of the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, Difference, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Computes the difference between the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, DifferenceAssign, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), operator_::sameTypeAs(0, "uint"),
                    "Decrements the first value by the second.");
STANDARD_OPERATOR_2(unsigned_integer, Division, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Divides the first integer by the second.");
STANDARD_OPERATOR_2(unsigned_integer, DivisionAssign, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), operator_::sameTypeAs(0, "uint"),
                    "Divides the first value by the second, assigning the new value.");
STANDARD_OPERATOR_2(unsigned_integer, Equal, type::Bool(), detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, Greater, type::Bool(), detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, GreaterEqual, type::Bool(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Compares the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, Lower, type::Bool(), detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, LowerEqual, type::Bool(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Compares the two integers.");
STANDARD_OPERATOR_2(unsigned_integer, Modulo, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Computes the modulus of the first integer divided by the second.");
STANDARD_OPERATOR_2(unsigned_integer, Multiple, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Multiplies the first integer by the second.");
STANDARD_OPERATOR_2(unsigned_integer, MultipleAssign, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), operator_::sameTypeAs(0, "uint"),
                    "Multiplies the first value by the second, assigning the new value.");
STANDARD_OPERATOR_2(unsigned_integer, Power, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Computes the first integer raised to the power of the second.");
STANDARD_OPERATOR_2(unsigned_integer, ShiftLeft, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), type::UnsignedInteger(type::Wildcard()),
                    "Shifts the integer to the left by the given number of bits.");
STANDARD_OPERATOR_2(unsigned_integer, ShiftRight, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), type::UnsignedInteger(type::Wildcard()),
                    "Shifts the integer to the right by the given number of bits.");
STANDARD_OPERATOR_2(unsigned_integer, Sum, detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    detail::widestTypeUnsigned(), "Computes the sum of the integers.");
STANDARD_OPERATOR_2(unsigned_integer, SumAssign, operator_::sameTypeAs(0, "uint"),
                    type::UnsignedInteger(type::Wildcard()), operator_::sameTypeAs(0, "uint"),
                    "Increments the first integer by the second.");
STANDARD_OPERATOR_2(unsigned_integer, Unequal, type::Bool(), detail::widestTypeUnsigned(), detail::widestTypeUnsigned(),
                    "Compares the two integers.");
STANDARD_OPERATOR_2x(unsigned_integer, CastToUnsigned, Cast, operator_::typedType(1, "uint<*>"),
                     type::UnsignedInteger(type::Wildcard()), type::Type_(type::UnsignedInteger(type::Wildcard())),
                     "Converts the value into another unsigned integer type, accepting any loss of information.");
STANDARD_OPERATOR_2x(unsigned_integer, CastToSigned, Cast, operator_::typedType(1, "int<*>"),
                     type::UnsignedInteger(type::Wildcard()), type::Type_(type::SignedInteger(type::Wildcard())),
                     "Converts the value into a signed integer type, accepting any loss of information.");
STANDARD_OPERATOR_2x(unsigned_integer, CastToReal, Cast, type::Real(), type::UnsignedInteger(type::Wildcard()),
                     type::Type_(type::Real()), "Converts the value into a real, accepting any loss of information.");
STANDARD_OPERATOR_2x(unsigned_integer, CastToEnum, Cast, operator_::typedType(1, "enum<*>"),
                     type::UnsignedInteger(type::Wildcard()), type::Type_(type::Enum(type::Wildcard())),
                     "Converts the value into an enum instance. The value does *not* need to correspond to "
                     "any of the target type's enumerator labels. It must not be larger than the maximum that a "
                     "*signed* 64-bit integer value can represent.");
STANDARD_OPERATOR_2x(unsigned_integer, CastToTime, Cast, type::Time(), type::UnsignedInteger(type::Wildcard()),
                     type::Type_(type::Time()), "Interprets the value as number of seconds since the UNIX epoch.");
STANDARD_OPERATOR_2x(unsigned_integer, CastToInterval, Cast, type::Interval(), type::UnsignedInteger(type::Wildcard()),
                     type::Type_(type::Interval()), "Interprets the value as number of seconds.");
STANDARD_OPERATOR_2x(unsigned_integer, CastToBool, Cast, type::Bool(), type::SignedInteger(type::Wildcard()),
                     type::Type_(type::Bool()), "Converts the value to a boolean by comparing against zero");

STANDARD_KEYWORD_CTOR(unsigned_integer, CtorSigned8, "uint8", type::UnsignedInteger(8),
                      type::SignedInteger(type::Wildcard()), "Creates a 8-bit unsigned integer value.");
STANDARD_KEYWORD_CTOR(unsigned_integer, CtorSigned16, "uint16", type::UnsignedInteger(16),
                      type::SignedInteger(type::Wildcard()), "Creates a 16-bit unsigned integer value.");
STANDARD_KEYWORD_CTOR(unsigned_integer, CtorSigned32, "uint32", type::UnsignedInteger(32),
                      type::SignedInteger(type::Wildcard()), "Creates a 32-bit unsigned integer value.");
STANDARD_KEYWORD_CTOR(unsigned_integer, CtorSigned64, "uint64", type::UnsignedInteger(64),
                      type::SignedInteger(type::Wildcard()), "Creates a 64-bit unsigned integer value.");
STANDARD_KEYWORD_CTOR(unsigned_integer, CtorUnsigned8, "uint8", type::UnsignedInteger(8),
                      type::UnsignedInteger(type::Wildcard()), "Creates a 8-bit unsigned integer value.");
STANDARD_KEYWORD_CTOR(unsigned_integer, CtorUnsigned16, "uint16", type::UnsignedInteger(16),
                      type::UnsignedInteger(type::Wildcard()), "Creates a 16-bit unsigned integer value.");
STANDARD_KEYWORD_CTOR(unsigned_integer, CtorUnsigned32, "uint32", type::UnsignedInteger(32),
                      type::UnsignedInteger(type::Wildcard()), "Creates a 32-bit unsigned integer value.");
STANDARD_KEYWORD_CTOR(unsigned_integer, CtorUnsigned64, "uint64", type::UnsignedInteger(64),
                      type::UnsignedInteger(type::Wildcard()), "Creates a 64-bit unsigned integer value.");

} // namespace hilti::operator_
