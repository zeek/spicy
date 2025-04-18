// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/forward.h>

#define HILTI_NODE_OPERATOR_CUSTOM_BASE(ns, cls, base)                                                                 \
    namespace ns {                                                                                                     \
    class cls : public base {                                                                                          \
    public:                                                                                                            \
        static cls* create(hilti::ASTContext* ctx, const hilti::Operator* op, hilti::QualifiedType* result,            \
                           const hilti::Expressions& operands, hilti::Meta meta) {                                     \
            return ctx->make<cls>(ctx, op, result, operands, std::move(meta));                                         \
        }                                                                                                              \
                                                                                                                       \
        HILTI_NODE_2(operator_::ns::cls, expression::ResolvedOperator, Expression, final);                             \
                                                                                                                       \
    private:                                                                                                           \
        cls(ASTContext* ctx, const hilti::Operator* op, QualifiedType* result, const Expressions& operands, Meta meta) \
            : base(ctx, NodeTags, op, result, operands, std::move(meta)) {}                                            \
    };                                                                                                                 \
    } // namespace ns

#define HILTI_NODE_OPERATOR(ns, cls) HILTI_NODE_OPERATOR_CUSTOM_BASE(ns, cls, hilti::expression::ResolvedOperator)
