// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <sys/types.h>

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::declaration {

/** AST node for a constant declaration. */
class Option : public Declaration {
public:
    auto init() const { return child<hilti::Expression>(1); }

    QualifiedType* type() const {
        if ( auto t = child<QualifiedType>(0) )
            return t;
        else
            return init()->type();
    }

    std::string_view displayName() const final { return "option"; }

    void setInit(ASTContext* ctx, hilti::Expression* e) { setChild(ctx, 1, e); }
    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t->recreateAsLhs(ctx)); }

    static auto create(ASTContext* ctx, ID id, QualifiedType* type, hilti::Expression* value, Meta meta = {}) {
        return ctx->make<Option>(ctx, {type->recreateAsLhs(ctx), value}, std::move(id), declaration::Linkage::Public,
                                 std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, hilti::Expression* value, const Meta& meta = {}) {
        return create(ctx, std::move(id), QualifiedType::createAuto(ctx, meta), value, meta);
    }

protected:
    Option(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), linkage, std::move(meta)) {}

    HILTI_NODE_1(declaration::Option, Declaration, final);
};

} // namespace hilti::declaration
