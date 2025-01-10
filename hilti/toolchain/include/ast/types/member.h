// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a type representing a member of another type. */
class Member : public UnqualifiedType {
public:
    const auto& id() const { return _id; }

    std::string_view typeClass() const final { return "member"; }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}};
        return UnqualifiedType::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, const ID& id, Meta meta = {}) {
        return ctx->make<Member>(ctx, id, std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Member>(ctx, Wildcard(), m);
    }

protected:
    Member(ASTContext* ctx, ID id, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {util::fmt("member(%s)", id)}, std::move(meta)), _id(std::move(id)) {
        assert(_id);
    }

    Member(ASTContext* ctx, Wildcard _, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"member(*)"}, std::move(meta)), _id("<wildcard>") {}

    HILTI_NODE_1(type::Member, UnqualifiedType, final);

private:
    ID _id;
};

} // namespace hilti::type
