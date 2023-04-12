// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/vector.h>

namespace hilti::operator_ {

// bytes::Iterator

STANDARD_OPERATOR_1(bytes::iterator, Deref, type::UnsignedInteger(8), type::constant(type::bytes::Iterator()),
                    "Returns the character the iterator is pointing to.");
STANDARD_OPERATOR_1(bytes::iterator, IncrPostfix, type::bytes::Iterator(), type::bytes::Iterator(),
                    "Advances the iterator by one byte, returning the previous position.");
STANDARD_OPERATOR_1(bytes::iterator, IncrPrefix, type::bytes::Iterator(), type::bytes::Iterator(),
                    "Advances the iterator by one byte, returning the new position.");

STANDARD_OPERATOR_2(
    bytes::iterator, Equal, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, Unequal, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, Lower, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, LowerEqual, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, Greater, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, GreaterEqual, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not referring to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, Difference, type::SignedInteger(64), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Returns the number of bytes between the two iterators. The result will be negative if the second iterator points "
    "to a location before the first. The result is undefined if the iterators do not refer to the same bytes "
    "instance.");
STANDARD_OPERATOR_2(bytes::iterator, Sum, type::bytes::Iterator(), type::constant(type::bytes::Iterator()),
                    type::UnsignedInteger(64),
                    "Returns an iterator which is pointing the given number of bytes beyond the one passed in.")
STANDARD_OPERATOR_2(bytes::iterator, SumAssign, type::bytes::Iterator(), type::bytes::Iterator(),
                    type::UnsignedInteger(64), "Advances the iterator by the given number of bytes.")

// Bytes

STANDARD_OPERATOR_1(bytes, Size, type::UnsignedInteger(64), type::constant(type::Bytes()),
                    "Returns the number of bytes the value contains.");
STANDARD_OPERATOR_2(bytes, Equal, type::Bool(), type::constant(type::Bytes()), type::constant(type::Bytes()),
                    "Compares two bytes values lexicographically.");
STANDARD_OPERATOR_2(bytes, Unequal, type::Bool(), type::constant(type::Bytes()), type::constant(type::Bytes()),
                    "Compares two bytes values lexicographically.");
STANDARD_OPERATOR_2(bytes, Greater, type::Bool(), type::constant(type::Bytes()), type::constant(type::Bytes()),
                    "Compares two bytes values lexicographically.");
STANDARD_OPERATOR_2(bytes, GreaterEqual, type::Bool(), type::constant(type::Bytes()), type::constant(type::Bytes()),
                    "Compares two bytes values lexicographically.");
STANDARD_OPERATOR_2(bytes, In, type::Bool(), type::constant(type::Bytes()), type::constant(type::Bytes()),
                    "Returns true if the right-hand-side value contains the left-hand-side value as a subsequence.");
STANDARD_OPERATOR_2(bytes, Lower, type::Bool(), type::constant(type::Bytes()), type::constant(type::Bytes()),
                    "Compares two bytes values lexicographically.");
STANDARD_OPERATOR_2(bytes, LowerEqual, type::Bool(), type::constant(type::Bytes()), type::constant(type::Bytes()),
                    "Compares two bytes values lexicographically.");
STANDARD_OPERATOR_2(bytes, Sum, type::constant(type::Bytes()), type::constant(type::Bytes()),
                    type::constant(type::Bytes()), "Returns the concatenation of two bytes values.");
STANDARD_OPERATOR_2x(bytes, SumAssignBytes, SumAssign, type::Bytes(), type::Bytes(), type::constant(type::Bytes()),
                     "Appends one bytes value to another.");
STANDARD_OPERATOR_2x(bytes, SumAssignStreamView, SumAssign, type::Bytes(), type::Bytes(),
                     type::constant(type::stream::View()), "Appends a view of stream data to a bytes instance.");
STANDARD_OPERATOR_2x(bytes, SumAssignUInt8, SumAssign, type::Bytes(), type::Bytes(), type::UnsignedInteger(8),
                     "Appends a single byte to the data.");

BEGIN_METHOD(bytes, Find)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::Tuple({type::Bool(), type::bytes::Iterator()}),
                                           .id = "find",
                                           .args = {{"needle", type::constant(type::Bytes())}},
                                           .doc = R"(
Searches *needle* in the value's content. Returns a tuple of a boolean and an
iterator. If *needle* was found, the boolean will be true and the iterator will
point to its first occurrence. If *needle* was not found, the boolean will be
false and the iterator will point to the last position so that everything before
it is guaranteed to not contain even a partial match of *needle*. Note that for a
simple yes/no result, you should use the ``in`` operator instead of this method,
as it's more efficient.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, LowerCase)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::constant(type::Bytes()),
                      .result = type::Bytes(),
                      .id = "lower",
                      .args = {{"charset", type::Enum(type::Wildcard()), false, builder::id("hilti::Charset::UTF8")},
                               {"errors", type::Enum(type::Wildcard()), false,
                                builder::id("hilti::DecodeErrorStrategy::REPLACE")}},
                      .doc = R"(
Returns a lower-case version of the bytes value, assuming it is
encoded in character set *charset*. If data is encountered that
*charset* cannot represent, it's handled according to the *errors*
strategy.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, UpperCase)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::constant(type::Bytes()),
                      .result = type::Bytes(),
                      .id = "upper",
                      .args = {{"charset", type::Enum(type::Wildcard()), false, builder::id("hilti::Charset::UTF8")},
                               {"errors", type::Enum(type::Wildcard()), false,
                                builder::id("hilti::DecodeErrorStrategy::REPLACE")}},
                      .doc = R"(
Returns an upper-case version of the bytes value, assuming it is
encoded in character set *charset*. If data is encountered that
*charset* cannot represent, it's handled according to the *errors*
strategy.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, At)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::bytes::Iterator(),
                                           .id = "at",
                                           .args = {{"i", type::UnsignedInteger(64)}},
                                           .doc = R"(
Returns an iterator representing the offset *i* inside the bytes value.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, Split)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::Vector(type::Bytes()),
                                           .id = "split",
                                           .args = {{"sep", type::constant(type::Bytes()), true}},
                                           .doc = R"(
Splits the bytes value at each occurrence of *sep* and returns a vector
containing the individual pieces, with all separators removed. If the separator
is not found, the returned vector will have the whole bytes value as its single
element. If the separator is not given, or empty, the split will take place at
sequences of white spaces.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, Split1)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::Tuple({type::Bytes(), type::Bytes()}),
                                           .id = "split1",
                                           .args = {{"sep", type::constant(type::Bytes()), true}},
                                           .doc = R"(
Splits the bytes value at the first occurrence of *sep* and returns the two parts
as a 2-tuple, with the separator removed. If the separator is not found, the
returned tuple will have the whole bytes value as its first element and an empty value
as its second element. If the separator is not given, or empty, the split will
take place at the first sequence of white spaces.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, StartsWith)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::Bool(),
                                           .id = "starts_with",
                                           .args = {{"b", type::constant(type::Bytes())}},
                                           .doc = R"(
Returns true if the bytes value starts with *b*.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, Strip)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::constant(type::Bytes()),
                      .result = type::Bytes(),
                      .id = "strip",
                      .args = {{"side", type::constant(type::Library("::hilti::rt::bytes::Side")), true},
                               {"set", type::constant(type::Bytes()), true}},
                      .doc = R"(
Removes leading and/or trailing sequences of all characters in *set* from the bytes
value. If *set* is not given, removes all white spaces. If *side* is given,
it indicates which side of the value should be stripped; ``Side::Both`` is the
default if not given.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, SubIterators)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::constant(type::Bytes()),
                      .result = type::Bytes(),
                      .id = "sub",
                      .args = {{"begin", type::bytes::Iterator()}, {"end", type::bytes::Iterator()}},
                      .doc = R"(
Returns the subsequence from *begin* to (but not including) *end*.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, SubIterator)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::Bytes(),
                                           .id = "sub",
                                           .args = {{"end", type::bytes::Iterator()}},
                                           .doc = R"(
Returns the subsequence from the value's beginning to (but not including) *end*.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, SubOffsets)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::constant(type::Bytes()),
                      .result = type::Bytes(),
                      .id = "sub",
                      .args = {{"begin", type::UnsignedInteger(64)}, {"end", type::UnsignedInteger(64)}},
                      .doc = R"(
Returns the subsequence from offset *begin* to (but not including) offset *end*.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, Join)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::Bytes(),
                                           .id = "join",
                                           .args = {{"parts", type::Vector(type::Wildcard())}},
                                           .doc =
                                               R"(
Returns the concatenation of all elements in the *parts* list rendered as
printable strings. The portions will be separated by the bytes value to
which this method is invoked as a member.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, ToIntAscii)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::SignedInteger(64),
                                           .id = "to_int",
                                           .args = {{"base", type::UnsignedInteger(64), true}},
                                           .doc =
                                               R"(
Interprets the data as representing an ASCII-encoded number and converts that
into a signed integer, using a base of *base*. *base* must be between 2 and 36.
If *base* is not given, the default is 10.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, ToUIntAscii)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::UnsignedInteger(64),
                                           .id = "to_uint",
                                           .args = {{"base", type::UnsignedInteger(64), true}},
                                           .doc =
                                               R"(
Interprets the data as representing an ASCII-encoded number and converts that
into an unsigned integer, using a base of *base*. *base* must be between 2 and
36. If *base* is not given, the default is 10.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, ToIntBinary)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::SignedInteger(64),
                                           .id = "to_int",
                                           .args = {{"byte_order", type::Enum(type::Wildcard())}},
                                           .doc =
                                               R"(
Interprets the ``bytes`` as representing an binary number encoded with the given
byte order, and converts it into signed integer.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, ToUIntBinary)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::UnsignedInteger(64),
                                           .id = "to_uint",
                                           .args = {{"byte_order", type::Enum(type::Wildcard())}},
                                           .doc =
                                               R"(
Interprets the ``bytes`` as representing an binary number encoded with the given
byte order, and converts it into an unsigned integer.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, ToTimeAscii)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::Time(),
                                           .id = "to_time",
                                           .args = {{"base", type::UnsignedInteger(64), true}},
                                           .doc =
                                               R"(
Interprets the ``bytes`` as representing a number of seconds since the epoch in
the form of an ASCII-encoded number, and converts it into a time value using a
base of *base*. If *base* is not given, the default is 10.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, ToTimeBinary)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Bytes()),
                                           .result = type::Time(),
                                           .id = "to_time",
                                           .args = {{"byte_order", type::Enum(type::Wildcard())}},
                                           .doc =
                                               R"(
Interprets the ``bytes`` as representing as number of seconds since the epoch in
the form of an binary number encoded with the given byte order, and converts it
into a time value.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, Decode)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::constant(type::Bytes()),
                      .result = type::String(),
                      .id = "decode",
                      .args = {{"charset", type::Enum(type::Wildcard()), false, builder::id("hilti::Charset::UTF8")},
                               {"errors", type::Enum(type::Wildcard()), false,
                                builder::id("hilti::DecodeErrorStrategy::REPLACE")}},
                      .doc =
                          R"(
Interprets the ``bytes`` as representing an binary string encoded with
the given character set, and converts it into a UTF8 string. If data
is encountered that *charset* or UTF* cannot represent, it's handled
according to the *errors* strategy.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(bytes, Match)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::constant(type::Bytes()),
                      .result = type::Result(type::Bytes()),
                      .id = "match",
                      .args = {{"regex", type::RegExp()}, {"group", type::UnsignedInteger(64), true}},
                      .doc =
                          R"(
Matches the ``bytes`` object against the regular expression *regex*. Returns
the matching part or, if *group* is given, then the corresponding subgroup. The
expression is considered anchored to the beginning of the data.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
