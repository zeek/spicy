// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/forward.h>

#define HILTI_NODE_OPERATOR(ns, cls)                                                                                   \
    namespace ns {                                                                                                     \
    class cls : public hilti::expression::ResolvedOperator {                                                           \
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
            : ResolvedOperator(ctx, NodeTags, op, result, operands, std::move(meta)) {}                                \
    };                                                                                                                 \
    } // namespace ns
