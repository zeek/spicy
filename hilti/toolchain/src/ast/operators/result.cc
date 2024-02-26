// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/result.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace result {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeResult(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "result",
            .doc =
                "Retrieves value stored inside the result instance. Will throw a ``NoResult`` exception if the "
                "result is in an error state.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, result::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class Error : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {.kind = Kind::MemberCall,
                .self = {parameter::Kind::In, builder->typeResult(type::Wildcard())},
                .member = "error",
                .result = {Constness::Const, builder->typeError()},
                .ns = "result",
                .doc =
                    "Retrieves the error stored inside the result instance. Will throw a ``NoError`` "
                    "exception if the result is not in an error state."};
    }

    HILTI_OPERATOR(hilti, result::Error);
};
HILTI_OPERATOR_IMPLEMENTATION(Error);

} // namespace result
} // namespace
