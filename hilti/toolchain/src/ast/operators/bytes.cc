// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/string.h>
#include <hilti/ast/types/vector.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace bytes {
namespace iterator {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .result = {Const, builder->typeUnsignedInteger(8)},
            .ns = "bytes::iterator",
            .doc = "Returns the character the iterator is pointing to.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class IncrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::IncrPostfix,
            .op0 = {parameter::Kind::InOut, builder->typeBytesIterator()},
            .result = {NonConst, builder->typeBytesIterator()},
            .ns = "bytes::iterator",
            .doc = "Advances the iterator by one byte, returning the previous position.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::IncrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPostfix);

class IncrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::IncrPrefix,
            .op0 = {parameter::Kind::InOut, builder->typeBytesIterator()},
            .result = {NonConst, builder->typeBytesIterator()},
            .ns = "bytes::iterator",
            .doc = "Advances the iterator by one byte, returning the new position.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::IncrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPrefix);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeBytesIterator()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same bytes "
                "value.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);


class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeBytesIterator()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same bytes "
                "value.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Lower,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeBytesIterator()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same bytes "
                "value.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);

class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::LowerEqual,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeBytesIterator()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same bytes "
                "value.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);

class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Greater,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeBytesIterator()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same bytes "
                "value.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::Greater)
};
HILTI_OPERATOR_IMPLEMENTATION(Greater);

class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::GreaterEqual,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeBytesIterator()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same bytes "
                "value.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);

class Difference : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Difference,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeBytesIterator()},
            .result = {Const, builder->typeSignedInteger(64)},
            .ns = "bytes::iterator",
            .doc =
                "Returns the number of bytes between the two iterators. The result will be negative if the second "
                "iterator points "
                "to a location before the first. The result is undefined if the iterators do not refer to the same "
                "bytes "
                "instance.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::Difference)
};
HILTI_OPERATOR_IMPLEMENTATION(Difference);

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Sum,
            .op0 = {parameter::Kind::In, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
            .result = {Const, builder->typeBytesIterator()},
            .ns = "bytes::iterator",
            .doc = "Returns an iterator which is pointing the given number of bytes beyond the one passed in.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum)

class SumAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::SumAssign,
            .op0 = {parameter::Kind::InOut, builder->typeBytesIterator()},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
            .result = {NonConst, builder->typeBytesIterator()},
            .ns = "bytes::iterator",
            .doc = "Advances the iterator by the given number of bytes.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::iterator::SumAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssign)

} // namespace iterator

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Size,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeUnsignedInteger(64)},
            .ns = "bytes",
            .doc = "Returns the number of bytes the value contains.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes",
            .doc = "Compares two bytes values lexicographically.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes",
            .doc = "Compares two bytes values lexicographically.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Greater,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes",
            .doc = "Compares two bytes values lexicographically.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::Greater)
};
HILTI_OPERATOR_IMPLEMENTATION(Greater);

class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::GreaterEqual,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes",
            .doc = "Compares two bytes values lexicographically.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);

class In : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::In,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes",
            .doc = "Returns true if the right-hand-side value contains the left-hand-side value as a subsequence.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::In)
};
HILTI_OPERATOR_IMPLEMENTATION(In);

class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Lower,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes",
            .doc = "Compares two bytes values lexicographically.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);

class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::LowerEqual,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBool()},
            .ns = "bytes",
            .doc = "Compares two bytes values lexicographically.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Sum,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = "Returns the concatenation of two bytes values.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum);

class SumAssignBytes : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::SumAssign,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeBytes()},
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = "Appends one bytes value to another.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::SumAssignBytes)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssignBytes);

class SumAssignStreamView : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::SumAssign,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeStreamView()},
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = "Appends a view of stream data to a bytes instance.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::SumAssignStreamView)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssignStreamView);

class SumAssignUInt8 : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::SumAssign,
            .op0 = {parameter::Kind::In, builder->typeBytes()},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(8)},
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = "Appends a single byte to the data.",
        };
    }
    HILTI_OPERATOR(hilti, bytes::SumAssignUInt8)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssignUInt8);

class Find : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {.kind = Kind::MemberCall,
                .self = {parameter::Kind::In, builder->typeBytes()},
                .member = "find",
                .param0 =
                    {
                        .name = "needle",
                        .type = {parameter::Kind::In, builder->typeBytes()},
                    },
                .result = {Const, builder->typeTuple({builder->qualifiedType(builder->typeBool(), Const),
                                                      builder->qualifiedType(builder->typeBytesIterator(), Const)})},
                .ns = "bytes",
                .doc = R"(
Searches *needle* in the value's content. Returns a tuple of a boolean and an
iterator. If *needle* was found, the boolean will be true and the iterator will
point to its first occurrence. If *needle* was not found, the boolean will be
false and the iterator will point to the last position so that everything before
it is guaranteed to not contain even a partial match of *needle*. Note that for a
simple yes/no result, you should use the ``in`` operator instead of this method,
as it's more efficient.
)"};
    }

    HILTI_OPERATOR(hilti, bytes::Find);
};
HILTI_OPERATOR_IMPLEMENTATION(Find);

class LowerCase : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "lower",
            .param0 =
                {
                    .name = "charset",
                    .type = {parameter::Kind::In, builder->typeName("hilti::Charset")},
                    .default_ = builder->expressionName("hilti::Charset::UTF8"),
                },
            .param1 =
                {
                    .name = "errors",
                    .type = {parameter::Kind::In, builder->typeName("hilti::DecodeErrorStrategy")},
                    .default_ = builder->expressionName("hilti::DecodeErrorStrategy::REPLACE"),
                },
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = R"(
Returns a lower-case version of the bytes value, assuming it is
encoded in character set *charset*. If data is encountered that
*charset* cannot represent, it's handled according to the *errors*
strategy.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::LowerCase);
};
HILTI_OPERATOR_IMPLEMENTATION(LowerCase);

class UpperCase : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "upper",
            .param0 =
                {
                    .name = "charset",
                    .type = {parameter::Kind::In, builder->typeName("hilti::Charset")},
                    .default_ = builder->expressionName("hilti::Charset::UTF8"),
                },
            .param1 =
                {
                    .name = "errors",
                    .type = {parameter::Kind::In, builder->typeName("hilti::DecodeErrorStrategy")},
                    .default_ = builder->expressionName("hilti::DecodeErrorStrategy::REPLACE"),
                },
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = R"(
Returns an upper-case version of the bytes value, assuming it is
encoded in character set *charset*. If data is encountered that
*charset* cannot represent, it's handled according to the *errors*
strategy.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::UpperCase);
};
HILTI_OPERATOR_IMPLEMENTATION(UpperCase);

class At : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "at",
            .param0 =
                {
                    .name = "i",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .result = {Const, builder->typeBytesIterator()},
            .ns = "bytes",
            .doc = R"(
Returns an iterator representing the offset *i* inside the bytes value.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::At);
};
HILTI_OPERATOR_IMPLEMENTATION(At);

class Split : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "split",
            .param0 =
                {
                    .name = "sep",
                    .type = {parameter::Kind::In, builder->typeBytes()},
                    .optional = true,
                },
            .result = {Const, builder->typeVector(builder->qualifiedType(builder->typeBytes(), NonConst))},
            .ns = "bytes",
            .doc = R"(
Splits the bytes value at each occurrence of *sep* and returns a vector
containing the individual pieces, with all separators removed. If the separator
is not found, the returned vector will have the whole bytes value as its single
element. If the separator is not given, or empty, the split will take place at
sequences of white spaces.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::Split);
};
HILTI_OPERATOR_IMPLEMENTATION(Split);

class Split1 : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "split1",
            .param0 =
                {
                    .name = "sep",
                    .type = {parameter::Kind::In, builder->typeBytes()},
                    .optional = true,
                },
            .result = {Const, builder->typeTuple({builder->qualifiedType(builder->typeBytes(), Const),
                                                  builder->qualifiedType(builder->typeBytes(), Const)})},
            .ns = "bytes",
            .doc = R"(
Splits the bytes value at the first occurrence of *sep* and returns the two parts
as a 2-tuple, with the separator removed. If the separator is not found, the
returned tuple will have the whole bytes value as its first element and an empty value
as its second element. If the separator is not given, or empty, the split will
take place at the first sequence of white spaces.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::Split1);
};
HILTI_OPERATOR_IMPLEMENTATION(Split1);

class StartsWith : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "starts_with",
            .param0 =
                {
                    .name = "b",
                    .type = {parameter::Kind::In, builder->typeBytes()},
                },
            .result = {Const, builder->typeBool()},
            .ns = "bytes",
            .doc = R"(
Returns true if the bytes value starts with *b*.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::StartsWith);
};
HILTI_OPERATOR_IMPLEMENTATION(StartsWith);

class Strip : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "strip",
            .param0 =
                {
                    .name = "side",
                    .type = {parameter::Kind::In, builder->typeName("hilti::Side")},
                    .optional = true,
                },
            .param1 =
                {
                    .name = "set",
                    .type = {parameter::Kind::In, builder->typeBytes()},
                    .optional = true,
                },
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = R"(
Removes leading and/or trailing sequences of all characters in *set* from the bytes
value. If *set* is not given, removes all white spaces. If *side* is given,
it indicates which side of the value should be stripped; ``Side::Both`` is the
default if not given.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::Strip);
};
HILTI_OPERATOR_IMPLEMENTATION(Strip);

class SubIterators : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "sub",
            .param0 =
                {
                    .name = "begin",
                    .type = {parameter::Kind::In, builder->typeBytesIterator()},
                },
            .param1 =
                {
                    .name = "end",
                    .type = {parameter::Kind::In, builder->typeBytesIterator()},
                },
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = R"(
Returns the subsequence from *begin* to (but not including) *end*.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::SubIterators);
};
HILTI_OPERATOR_IMPLEMENTATION(SubIterators);

class SubIterator : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "sub",
            .param0 =
                {
                    .name = "end",
                    .type = {parameter::Kind::In, builder->typeBytesIterator()},
                },
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = R"(
Returns the subsequence from the value's beginning to (but not including) *end*.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::SubIterator);
};
HILTI_OPERATOR_IMPLEMENTATION(SubIterator);

class SubOffsets : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "sub",
            .param0 =
                {
                    .name = "begin",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .param1 =
                {
                    .name = "end",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc = R"(
Returns the subsequence from offset *begin* to (but not including) offset *end*.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::SubOffsets);
};
HILTI_OPERATOR_IMPLEMENTATION(SubOffsets);

class Join : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "join",
            .param0 =
                {
                    .name = "parts",
                    .type = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
                },
            .result = {Const, builder->typeBytes()},
            .ns = "bytes",
            .doc =
                R"(
Returns the concatenation of all elements in the *parts* list rendered as
printable strings. The portions will be separated by the bytes value to
which this method is invoked as a member.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::Join);
};
HILTI_OPERATOR_IMPLEMENTATION(Join);

class ToIntAscii : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "to_int",
            .param0 =
                {
                    .name = "base",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                    .optional = true,
                },
            .result = {Const, builder->typeSignedInteger(64)},
            .ns = "bytes",
            .doc =
                R"(
Interprets the data as representing an ASCII-encoded number and converts that
into a signed integer, using a base of *base*. *base* must be between 2 and 36.
If *base* is not given, the default is 10.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::ToIntAscii);
};
HILTI_OPERATOR_IMPLEMENTATION(ToIntAscii);

class ToUIntAscii : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "to_uint",
            .param0 =
                {
                    .name = "base",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                    .optional = true,
                },
            .result = {Const, builder->typeUnsignedInteger(64)},
            .ns = "bytes",
            .doc =
                R"(
Interprets the data as representing an ASCII-encoded number and converts that
into an unsigned integer, using a base of *base*. *base* must be between 2 and
36. If *base* is not given, the default is 10.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::ToUIntAscii);
};
HILTI_OPERATOR_IMPLEMENTATION(ToUIntAscii);

class ToIntBinary : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "to_int",
            .param0 =
                {
                    .name = "byte_order",
                    .type = {parameter::Kind::In, builder->typeName("hilti::ByteOrder")},
                },
            .result = {Const, builder->typeSignedInteger(64)},
            .ns = "bytes",
            .doc =
                R"(
Interprets the ``bytes`` as representing an binary number encoded with the given
byte order, and converts it into signed integer.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::ToIntBinary);
};
HILTI_OPERATOR_IMPLEMENTATION(ToIntBinary);

class ToUIntBinary : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "to_uint",
            .param0 =
                {
                    .name = "byte_order",
                    .type = {parameter::Kind::In, builder->typeName("hilti::ByteOrder")},
                },
            .result = {Const, builder->typeUnsignedInteger(64)},
            .ns = "bytes",
            .doc =
                R"(
Interprets the ``bytes`` as representing an binary number encoded with the given
byte order, and converts it into an unsigned integer.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::ToUIntBinary);
};
HILTI_OPERATOR_IMPLEMENTATION(ToUIntBinary);

class ToTimeAscii : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "to_time",
            .param0 =
                {
                    .name = "base",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                    .optional = true,
                },
            .result = {Const, builder->typeTime()},
            .ns = "bytes",
            .doc =
                R"(
Interprets the ``bytes`` as representing a number of seconds since the epoch in
the form of an ASCII-encoded number, and converts it into a time value using a
base of *base*. If *base* is not given, the default is 10.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::ToTimeAscii);
};
HILTI_OPERATOR_IMPLEMENTATION(ToTimeAscii);

class ToTimeBinary : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "to_time",
            .param0 =
                {
                    .name = "byte_order",
                    .type = {parameter::Kind::In, builder->typeName("hilti::ByteOrder")},
                },
            .result = {Const, builder->typeTime()},
            .ns = "bytes",
            .doc =
                R"(
Interprets the ``bytes`` as representing as number of seconds since the epoch in
the form of an binary number encoded with the given byte order, and converts it
into a time value.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::ToTimeBinary);
};
HILTI_OPERATOR_IMPLEMENTATION(ToTimeBinary);

class Decode : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "decode",
            .param0 =
                {
                    .name = "charset",
                    .type = {parameter::Kind::In, builder->typeName("hilti::Charset")},
                    .default_ = builder->expressionName("hilti::Charset::UTF8"),
                },
            .param1 =
                {
                    .name = "errors",
                    .type = {parameter::Kind::In, builder->typeName("hilti::DecodeErrorStrategy")},
                    .default_ = builder->expressionName("hilti::DecodeErrorStrategy::REPLACE"),
                },
            .result = {Const, builder->typeString()},
            .ns = "bytes",
            .doc =
                R"(
Interprets the ``bytes`` as representing an binary string encoded with
the given character set, and converts it into a UTF8 string. If data
is encountered that *charset* or UTF* cannot represent, it's handled
according to the *errors* strategy.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::Decode);
};
HILTI_OPERATOR_IMPLEMENTATION(Decode);

class Match : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeBytes()},
            .member = "match",
            .param0 =
                {
                    .name = "regex",
                    .type = {parameter::Kind::In, builder->typeRegExp()},
                },
            .param1 =
                {
                    .name = "group",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                    .optional = true,
                },
            .result = {Const, builder->typeResult(builder->qualifiedType(builder->typeBytes(), Constness::Const))},
            .ns = "bytes",
            .doc =
                R"(
Matches the ``bytes`` object against the regular expression *regex*. Returns
the matching part or, if *group* is given, then the corresponding subgroup. The
expression is considered anchored to the beginning of the data.
)",
        };
    }

    HILTI_OPERATOR(hilti, bytes::Match);
};
HILTI_OPERATOR_IMPLEMENTATION(Match);

} // namespace bytes
} // namespace
