// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
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
        return UnqualifiedType::properties() + p;
    }

    static auto create(ASTContext* ctx, const ID& id, Meta meta = {}) {
        return std::shared_ptr<Member>(new Member(ctx, id, std::move(meta)));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return std::shared_ptr<Member>(new Member(ctx, Wildcard(), m));
    }

protected:
    Member(ASTContext* ctx, ID id, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {util::fmt("member(%s)", id)}, std::move(meta)), _id(std::move(id)) {
        assert(_id);
    }

    Member(ASTContext* ctx, Wildcard _, const Meta& meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"member(*)"}, meta), _id("<wildcard>") {}

    HILTI_NODE_1(type::Member, UnqualifiedType, final);

private:
    ID _id;
};

} // namespace hilti::type
