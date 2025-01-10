// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/result.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace result {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeResult(type::Wildcard())},
            .result_doc = "<type of stored value>",
            .ns = "result",
            .doc =
                "Retrieves the value stored inside the result instance. Will throw a ``NoResult`` exception if the "
                "result is in an error state.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->dereferencedType();
    }

    void validate(hilti::expression::ResolvedOperator* n) const final {
        if ( n->type()->type()->isA<type::Void>() )
            n->addError("value of type result<void> cannot be dereferenced");
    }

    HILTI_OPERATOR(hilti, result::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class Error : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{.kind = Kind::MemberCall,
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
