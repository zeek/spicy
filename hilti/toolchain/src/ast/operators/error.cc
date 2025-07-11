// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/error.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace error {

class Ctor : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "error",
            .param0 =
                {
                    .name = "msg",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeString()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeError()},
            .ns = "error",
            .doc = "Creates an error with the given message.",
            .skip_doc = true, // not available in Spicy source code
        };
    }

    HILTI_OPERATOR(hilti, error::Ctor)
};
HILTI_OPERATOR_IMPLEMENTATION(Ctor);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeError()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeError()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "error",
            .doc = "Compares two error descriptions lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, error::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeError()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeError()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "error",
            .doc = "Compares two error descriptions lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, error::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class Description : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeError()},
            .member = "description",
            .result = {.constness = Constness::Const, .type = builder->typeString()},
            .ns = "error",
            .doc = "Retrieves the textual description associated with the error.",
        };
    }

    HILTI_OPERATOR(hilti, error::Description);
};
HILTI_OPERATOR_IMPLEMENTATION(Description);

} // namespace error
} // namespace
