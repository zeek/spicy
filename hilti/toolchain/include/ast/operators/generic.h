// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/ast/operators/common.h>

namespace hilti {

namespace operator_ {
HILTI_NODE_OPERATOR(generic, CastedCoercion);
HILTI_NODE_OPERATOR(generic, Pack)
HILTI_NODE_OPERATOR(generic, Unpack)
HILTI_NODE_OPERATOR(generic, Begin)
HILTI_NODE_OPERATOR(generic, End)
HILTI_NODE_OPERATOR(generic, New)
} // namespace operator_

namespace generic {

/**
 * Operator created internally by the resolver for a cast expression
 * requesting a type coercion. This is mainly just a wrapper around a
 * CoercedExpression so that we don't loose the information that it was cast.
 */
class CastedCoercion final : public Operator {
public:
    CastedCoercion() : Operator(Meta(), false) {}
    ~CastedCoercion() final;

    operator_::Signature signature(Builder* builder) const final;
    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final;
    Result<ResolvedOperatorPtr> instantiate(Builder* builder, Expressions operands, const Meta& meta) const final;

    std::string name() const final { return "generic::CastedCoercion"; }
};

} // namespace generic
} // namespace hilti
