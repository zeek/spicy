// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for an expression referencing an ID. */
class Name : public Expression {
public:
    /** Returns the original source-level ID of the expression. */
    const auto& id() const { return _id; }

    /** If a fully-qualified ID has been set, returns it. */
    const auto& fullyQualifiedID() const { return _fqid; }

    /** If the resolver has resolved the name to a declaration, returns it. */
    Declaration* resolvedDeclaration() const {
        if ( ! _resolved_declaration_index )
            return nullptr;

        return context()->lookup(_resolved_declaration_index);
    }

    /** If the resolver has resolved the name to a declaration, returns its context index. */
    auto resolvedDeclarationIndex() const { return _resolved_declaration_index; }

    /**
     * Returns the expression's type. If the name has not been resolved yet,
     * that's `auto`. If it has been resolved, it's the type of the resolved
     * declaration. If it has been resolved to a type, the type will bewrapped
     * into `type::Type()`.
     */
    QualifiedType* type() const final;

    /**
     * Sets the declaration that the name has been resolved to. This then lets
     * `type()` return the declaration's type.

     * Should normally be called only by the resolver.
     */
    void setResolvedDeclarationIndex(ASTContext* ctx, ast::DeclarationIndex index);

    /**
     * Reverts the effect of `setResolvedDeclarationIndex()`, setting the
     * expression back to unresolved.
     */
    void clearResolvedDeclarationIndex(ASTContext* ctx) {
        if ( ! _resolved_declaration_index )
            return;

        _resolved_declaration_index = ast::DeclarationIndex::None;

        clearChildren();
        addChild(ctx, QualifiedType::createAuto(ctx, meta()));
    }

    /** Sets the original source-level ID of the expression. */
    void setID(ID id) { _id = std::move(id); }

    /** Records a fully-qualified ID for the name. */
    void setFullyQualifiedID(ID id) { _fqid = std::move(id); }

    node::Properties properties() const final;

    static auto create(ASTContext* ctx, const hilti::ID& id, const Meta& meta = {}) {
        return ctx->make<Name>(ctx, {QualifiedType::createAuto(ctx, meta)}, id, meta);
    }

protected:
    Name(ASTContext* ctx, Nodes children, hilti::ID id, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)), _id(std::move(id)), _context(ctx) {}

    ASTContext* context() const { return _context; }

    HILTI_NODE_1(expression::Name, Expression, final);

private:
    hilti::ID _id;
    hilti::ID _fqid;
    ast::DeclarationIndex _resolved_declaration_index;

    ASTContext* _context;
};

} // namespace hilti::expression
