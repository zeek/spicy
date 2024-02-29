// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

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
                    .type = {parameter::Kind::In, builder->typeString()},
                },
            .result = {Constness::Const, builder->typeError()},
            .ns = "error",
            .doc = "Creates an error with the given message.",
        };
    }

    HILTI_OPERATOR(hilti, error::Ctor)
};
HILTI_OPERATOR_IMPLEMENTATION(Ctor);

class Description : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeError()},
            .member = "description",
            .result = {Constness::Const, builder->typeString()},
            .ns = "error",
            .doc = "Retrieves the textual description associated with the error.",
        };
    }

    HILTI_OPERATOR(hilti, error::Description);
};
HILTI_OPERATOR_IMPLEMENTATION(Description);

} // namespace error
} // namespace
