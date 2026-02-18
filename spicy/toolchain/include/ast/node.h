// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/node-tag.h>
#include <hilti/ast/visitor-dispatcher.h>

#include <spicy/ast/visitor.h>

#define SPICY_NODE_0(CLASS, override_)                                                                                 \
    __HILTI_NODE_0(spicy, CLASS, override_)                                                                            \
                                                                                                                       \
    void dispatch(::hilti::visitor::Dispatcher& v) override_ {                                                         \
        if ( v.dispatcherTag() == spicy::visitor::Dispatcher::Spicy ) {                                                \
            auto sv = static_cast<spicy::visitor::Dispatcher*>(&v);                                                    \
            (*sv)(this);                                                                                               \
            (*sv)(static_cast<::hilti::Node*>(this));                                                                  \
        }                                                                                                              \
        else {                                                                                                         \
            v(this);                                                                                                   \
            v(static_cast<::hilti::Node*>(this));                                                                      \
        }                                                                                                              \
    }

#define SPICY_NODE_1(CLASS, BASE, override_)                                                                           \
    __HILTI_NODE_1(spicy, CLASS, BASE, override_)                                                                      \
                                                                                                                       \
    void dispatch(::hilti::visitor::Dispatcher& v) override_ {                                                         \
        if ( v.dispatcherTag() == spicy::visitor::Dispatcher::Spicy ) {                                                \
            auto sv = static_cast<spicy::visitor::Dispatcher*>(&v);                                                    \
            (*sv)(this);                                                                                               \
            (*sv)(static_cast<BASE*>(this));                                                                           \
            (*sv)(static_cast<::hilti::Node*>(this));                                                                  \
        }                                                                                                              \
        else {                                                                                                         \
            v(this);                                                                                                   \
            v(static_cast<BASE*>(this));                                                                               \
            v(static_cast<::hilti::Node*>(this));                                                                      \
        }                                                                                                              \
    }

#define SPICY_NODE_2(CLASS, BASE1, BASE2, override_)                                                                   \
    __HILTI_NODE_2(spicy, CLASS, BASE1, BASE2, override_)                                                              \
                                                                                                                       \
    void dispatch(::hilti::visitor::Dispatcher& v) override_ {                                                         \
        using namespace hilti;                                                                                         \
        if ( v.dispatcherTag() == spicy::visitor::Dispatcher::Spicy ) {                                                \
            auto sv = static_cast<spicy::visitor::Dispatcher*>(&v);                                                    \
            (*sv)(this);                                                                                               \
            (*sv)(static_cast<BASE1*>(this));                                                                          \
            (*sv)(static_cast<BASE2*>(this));                                                                          \
            (*sv)(static_cast<::hilti::Node*>(this));                                                                  \
        }                                                                                                              \
        else {                                                                                                         \
            v(static_cast<BASE1*>(this));                                                                              \
            v(static_cast<BASE2*>(this));                                                                              \
            v(static_cast<::hilti::Node*>(this));                                                                      \
        }                                                                                                              \
    }

#define SPICY_NODE_OPERATOR(ns, cls)                                                                                   \
    namespace ns {                                                                                                     \
    class cls : public hilti::expression::ResolvedOperator {                                                           \
    public:                                                                                                            \
        static cls* create(hilti::ASTContext* ctx, const hilti::Operator* op, hilti::QualifiedType* result,            \
                           const hilti::Expressions& operands, hilti::Meta meta) {                                     \
            return ctx->make<cls>(ctx, op, result, operands, std::move(meta));                                         \
        }                                                                                                              \
                                                                                                                       \
        SPICY_NODE_2(operator_::ns::cls, expression::ResolvedOperator, Expression, final);                             \
                                                                                                                       \
    private:                                                                                                           \
        cls(ASTContext* ctx, const hilti::Operator* op, QualifiedType* result, const Expressions& operands, Meta meta) \
            : ResolvedOperator(ctx, NodeTags, op, result, operands, std::move(meta)) {}                                \
    };                                                                                                                 \
    } // namespace ns
