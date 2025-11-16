// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/operator-registry.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/function.h>

namespace hilti::declaration {

/** AST node for a struct/union field declaration. */
class Field : public Declaration {
public:
    auto attributes() const { return child<AttributeSet>(1); }
    auto inlineFunction() const { return child<hilti::Function>(2); }

    /**
     * Returns an operator corresponding to a call to the member function that
     * the declaration corresponds to, if any.
     */
    auto operator_() const { return _operator; }

    QualifiedType* type() const {
        if ( const auto& func = inlineFunction() )
            return func->type();
        else
            return child<QualifiedType>(0);
    }

    bool isResolved(node::CycleDetector* cd = nullptr) const {
        if ( auto* func = inlineFunction() )
            return func->type()->isResolved(cd);

        if ( auto* type = child<QualifiedType>(0); type->type()->isA<type::Function>() )
            return true;
        else
            return type->isResolved(cd);
    }

    hilti::Expression* default_() const {
        if ( auto* a = attributes()->find(hilti::attribute::kind::Default) )
            return *a->valueAsExpression();
        else
            return {};
    }

    auto isAnonymous() const { return attributes()->find(hilti::attribute::kind::Anonymous) != nullptr; }
    auto isInternal() const { return attributes()->find(hilti::attribute::kind::Internal) != nullptr; }
    auto isOptional() const { return attributes()->find(hilti::attribute::kind::Optional) != nullptr; }
    auto isStatic() const { return attributes()->find(hilti::attribute::kind::Static) != nullptr; }
    auto isNoEmit() const { return attributes()->find(hilti::attribute::kind::NoEmit) != nullptr; }

    /**
     * Returns the type that has been semantically linked to this field. The
     * resolver sets the linked type to the field's parent type.
     *
     * This is a short-cut to manually querying the context for the type with
     * the index returned by `linkedTypeIndex()`.
     *
     * @param ctx AST context to use for the lookup
     * @return linked type, or nullptr if none
     */
    UnqualifiedType* linkedType(ASTContext* ctx) const {
        if ( _linked_type_index )
            return ctx->lookup(_linked_type_index);
        else
            return nullptr;
    }

    auto linkedTypeIndex() const { return _linked_type_index; }

    void setAttributes(ASTContext* ctx, AttributeSet* attrs) { setChild(ctx, 1, attrs); }
    void setOperator(const Operator* op) { _operator = op; }
    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }
    void setLinkedTypeIndex(ast::TypeIndex idx) {
        assert(idx);
        _linked_type_index = idx;
    }

    std::string_view displayName() const final { return "struct field"; }

    node::Properties properties() const final;

    static auto create(ASTContext* ctx, ID id, QualifiedType* type, AttributeSet* attrs, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        if ( attrs->find(hilti::attribute::kind::Static) )
            // make it assignable
            type = type->recreateAsLhs(ctx);

        return ctx->make<Field>(ctx, {type, attrs, nullptr}, std::move(id), std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, type::Function* ftype, AttributeSet* attrs, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Field>(ctx, {QualifiedType::create(ctx, ftype, Constness::Const), attrs, nullptr},
                                std::move(id), std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, hilti::Function* inline_func, AttributeSet* attrs, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Field>(ctx, {nullptr, attrs, inline_func}, std::move(id), std::move(meta));
    }

protected:
    Field(ASTContext* ctx, Nodes children, ID id, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), declaration::Linkage::Struct,
                      std::move(meta)) {}

    std::string _dump() const override;

    HILTI_NODE_1(declaration::Field, Declaration, final);

private:
    const Operator* _operator = nullptr;
    ast::TypeIndex _linked_type_index;
};

} // namespace hilti::declaration
