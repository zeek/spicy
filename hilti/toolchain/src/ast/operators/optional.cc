// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace optional {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeOptional(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "optional",
            .doc = "Returns the element stored, or throws an exception if none.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Optional>()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, optional::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

} // namespace optional
} // namespace
