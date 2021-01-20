// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/node_ref.h>
#include <hilti/ast/types/member.h>
#include <hilti/base/logger.h>

namespace hilti {
namespace expression {

/** AST node for a member-access expression. */
class Member : public NodeBase, hilti::trait::isExpression {
public:
    Member(ID id, Meta m = Meta()) : NodeBase({id, Type(type::Member(std::move(id))), node::none}, std::move(m)) {}
    Member(ID id, Type member_type, Meta m = Meta())
        : NodeBase({id, std::move(member_type), Type(type::Member(std::move(id)))}, std::move(m)) {}

    const auto& id() const { return child<ID>(0); }
    auto memberType() const { return type::effectiveOptionalType(childs()[1].tryAs<Type>()); }

    bool operator==(const Member& other) const { return id() == other.id() && type() == other.type(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return true; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return false; }
    /** Implements `Expression` interface. */
    Type type() const { return type::effectiveType(child<Type>(1)); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return true; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
