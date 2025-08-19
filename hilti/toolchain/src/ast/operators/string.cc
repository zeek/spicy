// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace string {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "string",
            .doc = "Compares two strings lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, string::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "string",
            .doc = "Compares two strings lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, string::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Size,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .result = {.constness = Constness::Const, .type = builder->typeUnsignedInteger(64)},
            .ns = "string",
            .doc = "Returns the number of characters the string contains.",
        };
    }

    HILTI_OPERATOR(hilti, string::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Sum,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .result = {.constness = Constness::Const, .type = builder->typeString()},
            .ns = "string",
            .doc = "Returns the concatenation of two strings.",
        };
    }

    HILTI_OPERATOR(hilti, string::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum);

class SumAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SumAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeString()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .result = {.constness = Constness::Const, .type = builder->typeString()},
            .ns = "string",
            .doc = "Appends the second string to the first.",
        };
    }

    HILTI_OPERATOR(hilti, string::SumAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssign);

class Modulo : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{.kind = Kind::Modulo,
                         .op0 = {.kind = parameter::Kind::In, .type = builder->typeString()},
                         .op1 = {.kind = parameter::Kind::In, .type = builder->typeAny()},
                         .result = {.constness = Constness::Const, .type = builder->typeString()},
                         .ns = "string",
                         .doc = "Renders a printf-style format string."};
    }

    HILTI_OPERATOR(hilti, string::Modulo)
};
HILTI_OPERATOR_IMPLEMENTATION(Modulo);

class Encode : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{.kind = Kind::MemberCall,
                         .self = {.kind = parameter::Kind::In, .type = builder->typeString()},
                         .member = "encode",
                         .param0 = {.name = "charset",
                                    .type = {.kind = parameter::Kind::In, .type = builder->typeName("hilti::Charset")},
                                    .default_ = builder->expressionName("hilti::Charset::UTF8")},
                         .param1 = {.name = "errors",
                                    .type = {.kind = parameter::Kind::In,
                                             .type = builder->typeName("hilti::DecodeErrorStrategy")},
                                    .default_ = builder->expressionName("hilti::DecodeErrorStrategy::REPLACE")},
                         .result = {.constness = Constness::Const, .type = builder->typeBytes()},
                         .ns = "string",
                         .doc =
                             "Converts the string into a binary representation encoded with the given character set."};
    };

    HILTI_OPERATOR(hilti, string::Encode);
};
HILTI_OPERATOR_IMPLEMENTATION(Encode);

class Split : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .member = "split",
            .param0 =
                {
                    .name = "sep",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeString()},
                    .optional = true,
                },
            .result = {.constness = Constness::Const,
                       .type = builder->typeVector(builder->qualifiedType(builder->typeString(), Constness::Mutable))},
            .ns = "string",
            .doc = R"(
Splits the string value at each occurrence of *sep* and returns a vector
containing the individual pieces, with all separators removed. If the separator
is not found, or if the separator is empty, the returned vector will have the
whole string value as its single element. If the separator is not given, the
split will occur at sequences of white spaces.
)",
        };
    }

    HILTI_OPERATOR(hilti, string::Split);
};
HILTI_OPERATOR_IMPLEMENTATION(Split);

class Split1 : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .member = "split1",
            .param0 =
                {
                    .name = "sep",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeString()},
                    .optional = true,
                },
            .result = {.constness = Constness::Const,
                       .type = builder->typeTuple(
                           QualifiedTypes{builder->qualifiedType(builder->typeString(), Constness::Const),
                                          builder->qualifiedType(builder->typeString(), Constness::Const)})},
            .ns = "string",
            .doc = R"(
Splits the string value at the first occurrence of *sep* and returns the two parts
as a 2-tuple, with the separator removed. If the separator is not found, the
returned tuple will have the whole string value as its first element and an empty
value as its second element. If the separator is empty, the returned tuple will
have an empty first element and the whole string value as its second element. If
the separator is not provided, the split will occur at the first sequence of
white spaces.
)",
        };
    }

    HILTI_OPERATOR(hilti, string::Split1);
};
HILTI_OPERATOR_IMPLEMENTATION(Split1);

class StartsWith : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .member = "starts_with",
            .param0 =
                {
                    .name = "prefix",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeString()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "string",
            .doc = "Returns true if the string value starts with *prefix*.",
        };
    }

    HILTI_OPERATOR(hilti, string::StartsWith);
};
HILTI_OPERATOR_IMPLEMENTATION(StartsWith);

class EndsWith : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .member = "ends_with",
            .param0 =
                {
                    .name = "suffix",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeString()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "string",
            .doc = "Returns true if the string value ends with *suffix*.",
        };
    }

    HILTI_OPERATOR(hilti, string::EndsWith);
};
HILTI_OPERATOR_IMPLEMENTATION(EndsWith);

class LowerCase : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .member = "lower",
            .result = {.constness = Constness::Const, .type = builder->typeString()},
            .ns = "string",
            .doc = "Returns a lower-case version of the string value.",
        };
    }

    HILTI_OPERATOR(hilti, string::LowerCase);
};
HILTI_OPERATOR_IMPLEMENTATION(LowerCase);

class UpperCase : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeString()},
            .member = "upper",
            .result = {.constness = Constness::Const, .type = builder->typeString()},
            .ns = "string",
            .doc = "Returns an upper-case version of the string value.",
        };
    }

    HILTI_OPERATOR(hilti, string::UpperCase);
};
HILTI_OPERATOR_IMPLEMENTATION(UpperCase);

} // namespace string
} // namespace
