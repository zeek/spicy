// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/vector.h>

namespace hilti {
namespace operator_ {

// bytes::Iterator

STANDARD_OPERATOR_1(bytes::iterator, Deref, type::UnsignedInteger(8), type::constant(type::bytes::Iterator()),
                    "Returns the byte the iterator is pointing to.");
STANDARD_OPERATOR_1(bytes::iterator, IncrPostfix, type::bytes::Iterator(), type::bytes::Iterator(),
                    "Advances the iterator by one byte, returning the previous position.");
STANDARD_OPERATOR_1(bytes::iterator, IncrPrefix, type::bytes::Iterator(), type::bytes::Iterator(),
                    "Advances the iterator by one byte, returning the new position.");

STANDARD_OPERATOR_2(
    bytes::iterator, Equal, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not refering to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, Unequal, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not refering to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, Lower, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not refering to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, LowerEqual, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not refering to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, Greater, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not refering to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, GreaterEqual, type::Bool(), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Compares the two positions. The result is undefined if they are not refering to the same bytes value.");
STANDARD_OPERATOR_2(
    bytes::iterator, Difference, type::SignedInteger(64), type::constant(type::bytes::Iterator()),
    type::constant(type::bytes::Iterator()),
    "Returns the number of bytes between the two iterators. The result will be negative if the second iterator points "
    "to a location before the first. The result is undefined if the iterators do not refer to the same bytes instace.");
STANDARD_OPERATOR_2(bytes::iterator, Sum, type::bytes::Iterator(), type::constant(type::bytes::Iterator()),
                    type::UnsignedInteger(64), "Advances the iterator by the given number of bytes.")
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
                    type::constant(type::Bytes()), "Returns the concatentation of two bytes values.");
STANDARD_OPERATOR_2x(bytes, SumAssignBytes, SumAssign, type::Bytes(), type::Bytes(), type::constant(type::Bytes()),
                     "Appends one bytes value to another.");
STANDARD_OPERATOR_2x(bytes, SumAssignStreamView, SumAssign, type::Bytes(), type::Bytes(),
                     type::constant(type::stream::View()), "Appends a view of stream data to a bytes instance.");

BEGIN_METHOD(bytes, Find)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Tuple({type::Bool(), type::bytes::Iterator()}),
                         .id = "find",
                         .args = {{.id = "needle", .type = type::constant(type::Bytes())}},
                         .doc = R"(
Searches *needle* in the value's content. Returns a tuple of a boolean and an
iterator. If *needle* was found, the boolean will be true and the iterator will
point to its first occurance. If *needle* was not found, the boolean will be
false and the iterator will point to the last position so that everything before
it is guaranteed to not contain even a partial match of *needle*. Note that for a
simple yes/no result, you should use the ``in`` operator instead of this method,
as it's more efficient.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, LowerCase)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Bytes(),
                         .id = "lower",
                         .args = {{.id = "charset",
                                   .type = type::Enum(type::Wildcard()),
                                   .default_ = builder::id("hilti::Charset::UTF8")}},
                         .doc = R"(
Returns a lower-case version of the bytes value, assuming its encoded in character set *charset*.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, UpperCase)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Bytes(),
                         .id = "upper",
                         .args = {{.id = "charset",
                                   .type = type::Enum(type::Wildcard()),
                                   .default_ = builder::id("hilti::Charset::UTF8")}},
                         .doc = R"(
Returns an upper-case version of the bytes value, assuming its encoded in character set *charset*.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, At)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::bytes::Iterator(),
                         .id = "at",
                         .args = {{.id = "i", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Returns an iterator representing the offset *i* inside the bytes value.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, Split)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Vector(type::Bytes()),
                         .id = "split",
                         .args = {{.id = "sep", .type = type::constant(type::Bytes()), .optional = true}},
                         .doc = R"(
Splits the bytes value at each occurence of *sep* and returns a vector
containing the individual pieces, with all separators removed. If the separator
is not found, the returned vector will have the whole bytes value as its single
element. If the separator is not given, or empty, the split will take place at
sequences of white spaces.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, Split1)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Tuple({type::Bytes(), type::Bytes()}),
                         .id = "split1",
                         .args = {{.id = "sep", .type = type::constant(type::Bytes()), .optional = true}},
                         .doc = R"(
Splits the bytes value at the first occurence of *sep* and returns the two parts
as a 2-tuple, with the separator removed. If the separator is not found, the
returned tuple will have the whole bytes value as its first element and an empty value
as its second element. If the separator is not given, or empty, the split will
take place at the first sequence of white spaces.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, StartsWith)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Bool(),
                         .id = "starts_with",
                         .args = {{.id = "b", .type = type::constant(type::Bytes())}},
                         .doc = R"(
Returns true if the bytes value starts with *b*.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, Strip)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Bytes(),
                         .id = "strip",
                         .args = {{.id = "side",
                                   .type = type::constant(type::Library("hilti::rt::bytes::Side")),
                                   .optional = true},
                                  {.id = "set", .type = type::constant(type::Bytes()), .optional = true}},
                         .doc = R"(
Removes leading and/or trailing sequences of all characters in *set* from the bytes
value. If *set* is not given, removes all white spaces. If *side* is given,
it indicates which side of the value should be stripped; ``Side::Both`` is the
default if not given.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, SubIterators)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Bytes(),
                         .id = "sub",
                         .args = {{.id = "begin", .type = type::bytes::Iterator()},
                                  {.id = "end", .type = type::bytes::Iterator()}},
                         .doc = R"(
Returns the subsequence from *begin* to (but not including) *end*.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, SubIterator)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Bytes(),
                         .id = "sub",
                         .args = {{.id = "end", .type = type::bytes::Iterator()}},
                         .doc = R"(
Returns the subsequence from the value's beginning to (but not including) *end*.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, SubOffsets)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Bytes(),
                         .id = "sub",
                         .args = {{.id = "begin", .type = type::UnsignedInteger(64)},
                                  {.id = "end", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Returns the subsequence from offset *begin* to (but not including) offset *end*.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, Join)
    auto signature() const {
        return Signature{
            .self = type::constant(type::Bytes()),
            .result = type::Bytes(),
            .id = "join",
            .args = {{.id = "parts", .type = type::Vector(type::Wildcard())}},
            .doc =
                R"(Returns the concatenation of all elements in the *parts* list rendered as printable-strings and separated by the bytes value providing this method.)"};
    }
END_METHOD

BEGIN_METHOD(bytes, ToIntAscii)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::SignedInteger(64),
                         .id = "to_int",
                         .args = {{.id = "base", .type = type::UnsignedInteger(64), .optional = true}},
                         .doc =
                             R"(
Interprets the data as representing an ASCII-encoded number and converts
that into a signed integer, using a base of *base*. If *base* is not given, the
default is 10.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, ToUIntAscii)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::UnsignedInteger(64),
                         .id = "to_uint",
                         .args = {{.id = "base", .type = type::UnsignedInteger(64), .optional = true}},
                         .doc =
                             R"(
Interprets the data as representing an ASCII-encoded number and converts
that into an unsigned integer, using a base of *base*. If *base* is not given, the
default is 10.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, ToIntBinary)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::SignedInteger(64),
                         .id = "to_int",
                         .args = {{.id = "byte_order", .type = type::Enum(type::Wildcard())}},
                         .doc =
                             R"(
Interprets the ``bytes`` as representing an binary number encoded with the given
byte order, and converts it into signed integer.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, ToUIntBinary)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::UnsignedInteger(64),
                         .id = "to_uint",
                         .args = {{.id = "byte_order", .type = type::Enum(type::Wildcard())}},
                         .doc =
                             R"(
Interprets the ``bytes`` as representing an binary number encoded with the given
byte order, and converts it into an unsigned integer.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, ToTimeAscii)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Time(),
                         .id = "to_time",
                         .args = {{.id = "base", .type = type::UnsignedInteger(64), .optional = true}},
                         .doc =
                             R"(
Interprets the ``bytes`` as representing a number of seconds since the epoch in
the form of an ASCII-encoded number, and converts it into a time value using a
base of *base*. If *base* is not given, the default is 10.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, ToTimeBinary)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Time(),
                         .id = "to_time",
                         .args = {{.id = "byte_order", .type = type::Enum(type::Wildcard())}},
                         .doc =
                             R"(
Interprets the ``bytes`` as representing as number of seconds since the epoch in
the form of an binary number encoded with the given byte order, and converts it
into a time value.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, Decode)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::String(),
                         .id = "decode",
                         .args = {{.id = "charset", .type = type::Enum(type::Wildcard())}},
                         .doc =
                             R"(
Interprets the ``bytes`` as representing an binary string encoded with the given
character set, and converts it into a UTF8 string.
)"};
    }
END_METHOD

BEGIN_METHOD(bytes, Match)
    auto signature() const {
        return Signature{.self = type::constant(type::Bytes()),
                         .result = type::Result(type::Bytes()),
                         .id = "match",
                         .args = {{.id = "regex", .type = type::RegExp()},
                                  {.id = "group", .type = type::UnsignedInteger(64), .optional = true}},
                         .doc =
                             R"(
Matches the ``bytes`` object against the regular expression *regex*. Returns the matching
part or, if *group* is given the corresponding subgroup.
)"};
    }
END_METHOD

} // namespace operator_
} // namespace hilti
