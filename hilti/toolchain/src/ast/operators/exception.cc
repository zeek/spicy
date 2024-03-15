// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace exception {

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/exception.h>

class Ctor : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .self = {parameter::Kind::In, builder->ctorType(builder->typeException(type::Wildcard()))},
            .param0 =
                {
                    .name = "msg",
                    .type = {parameter::Kind::In, builder->typeString()},
                },
            .result_doc = "exception value",
            .ns = "exception",
            .doc = R"(
Instantiates an instance of the exception type carrying the error message *msg*.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Type_>()->typeValue();
    }

    HILTI_OPERATOR(hilti, exception::Ctor)
};
HILTI_OPERATOR_IMPLEMENTATION(Ctor);

class Description : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeException(type::Wildcard())},
            .member = "description",
            .result = {Constness::Const, builder->typeString()},
            .ns = "exception",
            .doc = R"(
Returns the textual message associated with an exception object.
)",
        };
    }

    HILTI_OPERATOR(hilti, exception::Description);
};
HILTI_OPERATOR_IMPLEMENTATION(Description);

} // namespace exception
} // namespace
