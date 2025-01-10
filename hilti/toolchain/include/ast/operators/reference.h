// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>

namespace hilti::operator_ {

namespace reference {

/** Joint base class for all the references' `Deref` AST nodes. */
class DerefBase : public expression::ResolvedOperator {
public:
    using expression::ResolvedOperator::ResolvedOperator;

    /**
     * Returns true if the operator has been marked as automatically created by
     * the coercer.
     */
    auto isAutomaticCoercion() const { return _is_coercion; }

    /** Marks the operators as automatically created by the coercer. */
    void setIsAutomaticCoercion(bool is_coercion) { _is_coercion = is_coercion; }

    node::Properties properties() const final {
        auto p = node::Properties{{"auto", _is_coercion}};
        return expression::ResolvedOperator::properties() + std::move(p);
    }

private:
    bool _is_coercion = false;
};
} // namespace reference

HILTI_NODE_OPERATOR_CUSTOM_BASE(strong_reference, Deref, reference::DerefBase)
HILTI_NODE_OPERATOR(strong_reference, Equal)
HILTI_NODE_OPERATOR(strong_reference, Unequal)
HILTI_NODE_OPERATOR_CUSTOM_BASE(weak_reference, Deref, reference::DerefBase)
HILTI_NODE_OPERATOR(weak_reference, Equal)
HILTI_NODE_OPERATOR(weak_reference, Unequal)
HILTI_NODE_OPERATOR_CUSTOM_BASE(value_reference, Deref, reference::DerefBase)
HILTI_NODE_OPERATOR(value_reference, Equal)
HILTI_NODE_OPERATOR(value_reference, Unequal)

} // namespace hilti::operator_
