// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::declaration {

/** AST node for a global variable declaration. */
class GlobalVariable : public Declaration {
public:
    auto type() const { return child<QualifiedType>(0); }
    auto init() const { return child<hilti::Expression>(1); }
    auto typeArguments() const { return children<hilti::Expression>(2, {}); }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t->recreateAsLhs(ctx)); }
    void setInit(ASTContext* ctx, hilti::Expression* init) { setChild(ctx, 1, init); }

    void setTypeArguments(ASTContext* ctx, Expressions args) {
        removeChildren(2, {});
        addChildren(ctx, std::move(args));
    }

    std::string_view displayName() const final { return "global variable"; }

    static auto create(ASTContext* ctx, ID id, QualifiedType* type, Expressions args, hilti::Expression* init = nullptr,
                       declaration::Linkage linkage = Linkage::Private, Meta meta = {}) {
        return ctx->make<GlobalVariable>(ctx, node::flatten(type->recreateAsLhs(ctx), init, std::move(args)),
                                         std::move(id), linkage, std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, QualifiedType* type, hilti::Expression* init = nullptr,
                       declaration::Linkage linkage = Linkage::Private, Meta meta = {}) {
        return create(ctx, std::move(id), type->recreateAsLhs(ctx), {}, init, linkage, std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, QualifiedType* type, declaration::Linkage linkage = Linkage::Private,
                       Meta meta = {}) {
        return create(ctx, std::move(id), type->recreateAsLhs(ctx), {}, nullptr, linkage, std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, hilti::Expression* init, declaration::Linkage linkage = Linkage::Private,
                       const Meta& meta = {}) {
        return create(ctx, std::move(id), QualifiedType::createAuto(ctx, meta), {}, init, linkage, meta);
    }

    static auto create(ASTContext* ctx, ID id, declaration::Linkage linkage = Linkage::Private, const Meta& meta = {}) {
        return create(ctx, std::move(id), QualifiedType::createAuto(ctx, meta), linkage, meta);
    }

protected:
    GlobalVariable(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), linkage, std::move(meta)) {}

    HILTI_NODE_1(declaration::GlobalVariable, Declaration, final);
};

} // namespace hilti::declaration
