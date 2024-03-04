// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <sys/types.h>

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::declaration {

/** AST node for a constant declaration. */
class Constant : public Declaration {
public:
    auto value() const { return child<hilti::Expression>(1); }

    QualifiedTypePtr type() const {
        if ( auto t = child<QualifiedType>(0) )
            return t;
        else
            return value()->type();
    }

    std::string_view displayName() const final { return "constant"; }

    void setValue(ASTContext* ctx, ExpressionPtr e) { setChild(ctx, 1, std::move(e)); }

    static auto create(ASTContext* ctx, ID id, const QualifiedTypePtr& type, const ExpressionPtr& value,
                       declaration::Linkage linkage = Linkage::Private, Meta meta = {}) {
        QualifiedTypePtr t = type;

        if ( t )
            t = t->recreateAsConst(ctx);

        return std::shared_ptr<Constant>(new Constant(ctx, {t, value}, std::move(id), linkage, std::move(meta)));
    }

    static auto create(ASTContext* ctx, ID id, const ExpressionPtr& value,
                       declaration::Linkage linkage = Linkage::Private, Meta meta = {}) {
        return create(ctx, std::move(id), {}, value, linkage, std::move(meta));
    }

protected:
    Constant(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), linkage, std::move(meta)) {
        assert(! child(0) || child(0)->as<QualifiedType>()->isConstant());
    }

    HILTI_NODE_1(declaration::Constant, Declaration, final);
};

} // namespace hilti::declaration
