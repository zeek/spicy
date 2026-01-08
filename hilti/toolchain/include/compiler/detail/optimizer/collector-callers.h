// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/compiler/detail/optimizer/pass.h>

namespace hilti::detail::optimizer {

/** Collects a mapping of all call operators to their uses. */
struct CollectorCallers : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    // Maps the call operator to the places where's been used.
    using Callers = std::map<const Operator*, std::vector<expression::ResolvedOperator*>>;
    Callers callers;

    const Callers::mapped_type* uses(const Operator* x) const {
        if ( ! callers.contains(x) )
            return nullptr;

        return &callers.at(x);
    }

    void operator()(operator_::function::Call* n) final { callers[&n->operator_()].push_back(n); }

    void operator()(operator_::struct_::MemberCall* n) final { callers[&n->operator_()].push_back(n); }
};

} // namespace hilti::detail::optimizer
