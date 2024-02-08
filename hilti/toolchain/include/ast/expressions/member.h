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

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}};
        return Expression::properties() + p;
    }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& member_type, const hilti::ID& id,
                       const Meta& meta = {}) {
        return std::shared_ptr<Member>(new Member(ctx, {member_type}, id, meta));
    }

    static auto create(ASTContext* ctx, const hilti::ID& id, const Meta& meta = {}) {
        return create(ctx, QualifiedType::create(ctx, type::Member::create(ctx, id, meta), Constness::Const, meta), id,
                      meta);
    }

protected:
    Member(ASTContext* ctx, Nodes children, hilti::ID id, Meta meta)
        : Expression(ctx, std::move(children), std::move(meta)), _id(std::move(id)) {}

    HILTI_NODE(hilti, Member)

private:
    hilti::ID _id;
};

} // namespace hilti::expression
