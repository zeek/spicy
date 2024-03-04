// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a statement representing a declaration. */
class Declaration : public Statement {
public:
    auto declaration() const { return child<::hilti::Declaration>(0); }

    static auto create(ASTContext* ctx, const hilti::DeclarationPtr& d, Meta meta = {}) {
        return std::shared_ptr<Declaration>(new Declaration(ctx, {d}, std::move(meta)));
    }

protected:
    Declaration(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Declaration, Statement, final);
};

} // namespace hilti::statement
