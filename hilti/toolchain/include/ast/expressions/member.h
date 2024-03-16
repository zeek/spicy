// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/member.h>

namespace hilti::expression {

/** AST node for a member expression. */
class Member : public Expression {
public:
    const auto& id() const { return _id; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}};
        return Expression::properties() + p;
    }

    static auto create(ASTContext* ctx, QualifiedType* member_type, const hilti::ID& id, Meta meta = {}) {
        return ctx->make<Member>(ctx, {member_type}, id, std::move(meta));
    }

    static auto create(ASTContext* ctx, const hilti::ID& id, const Meta& meta = {}) {
        return create(ctx, QualifiedType::create(ctx, type::Member::create(ctx, id, meta), Constness::Const, meta), id,
                      meta);
    }

protected:
    Member(ASTContext* ctx, Nodes children, hilti::ID id, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)), _id(std::move(id)) {}

    HILTI_NODE_1(expression::Member, Expression, final);

private:
    hilti::ID _id;
};

} // namespace hilti::expression
