// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
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
    const auto& id() const { return _id; }

    DeclarationPtr resolvedDeclaration() {
        if ( ! _resolved_declaration_index )
            return nullptr;

        return context()->lookup(_resolved_declaration_index);
    }

    auto resolvedDeclarationIndex() const { return _resolved_declaration_index; }

    QualifiedTypePtr type() const final;

    void setResolvedDeclarationIndex(ASTContext* ctx, ast::DeclarationIndex index);

    void clearResolvedDeclarationIndex(ASTContext* ctx) {
        if ( ! _resolved_declaration_index )
            return;

        _resolved_declaration_index = ast::DeclarationIndex::None;

        clearChildren();
        addChild(ctx, QualifiedType::createAuto(ctx, meta()));
    }

    void setID(ID id) { _id = std::move(id); }

    node::Properties properties() const final;

    static auto create(ASTContext* ctx, const hilti::ID& id, const Meta& meta = {}) {
        return std::shared_ptr<Name>(new Name(ctx, {QualifiedType::createAuto(ctx, meta)}, id, meta));
    }

protected:
    Name(ASTContext* ctx, Nodes children, hilti::ID id, Meta meta)
        : Expression(ctx, std::move(children), std::move(meta)), _id(std::move(id)), _context(ctx) {}

    ASTContext* context() const { return _context; }

    HILTI_NODE(hilti, Name)

private:
    hilti::ID _id;
    ast::DeclarationIndex _resolved_declaration_index;

    ASTContext* _context;
};

} // namespace hilti::expression
