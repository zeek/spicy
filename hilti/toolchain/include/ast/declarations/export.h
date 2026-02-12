// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>

namespace hilti::declaration {

/** AST node for an export declaration. */
class Export : public Declaration {
public:
    /** If the resolver has resolved the ID to a declaration, returns it. */
    Declaration* resolvedDeclaration(ASTContext* context) const {
        if ( ! _resolved_declaration_index )
            return nullptr;

        return context->lookup(_resolved_declaration_index);
    }

    /** If the resolver has resolved the name to a declaration, returns its context index. */
    auto resolvedDeclarationIndex() const { return _resolved_declaration_index; }

    /**
     * Sets the declaration that the name has been resolved to.
     *
     * Should normally be called only by the resolver.
     */
    void setResolvedDeclarationIndex(ASTContext* ctx, ast::DeclarationIndex index) {
        assert(index);
        _resolved_declaration_index = index;
    }

    std::string_view displayName() const final { return "export"; }

    static auto create(ASTContext* ctx, ID id, Meta meta = {}) {
        return ctx->make<Export>(ctx, {}, std::move(id), std::move(meta));
    }

protected:
    Export(ASTContext* ctx, Nodes children, ID id, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), Linkage::Private, std::move(meta)) {}

    HILTI_NODE_1(declaration::Export, Declaration, final);

private:
    ast::DeclarationIndex _resolved_declaration_index;
};

} // namespace hilti::declaration
