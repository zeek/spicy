// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/forward.h>

#define HILTI_NODE_OPERATOR(scope, ns, cls)                                                                            \
    namespace ns {                                                                                                     \
    class cls : public hilti::expression::ResolvedOperator {                                                           \
    public:                                                                                                            \
        static std::shared_ptr<cls> create(ASTContext* ctx, const hilti::Operator* op, const QualifiedTypePtr& result, \
                                           const Expressions& operands, const hilti::Meta& meta) {                     \
            return std::shared_ptr<cls>(new cls(ctx, op, result, operands, meta));                                     \
        }                                                                                                              \
                                                                                                                       \
        HILTI_NODE(scope, cls)                                                                                         \
                                                                                                                       \
    private:                                                                                                           \
        using hilti::expression::ResolvedOperator::ResolvedOperator;                                                   \
    };                                                                                                                 \
    } // namespace ns
