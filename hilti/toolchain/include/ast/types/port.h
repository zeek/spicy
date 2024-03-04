// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `port` type. */
class Port : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "port"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) {
        return std::shared_ptr<Port>(new Port(ctx, std::move(meta)));
    }

protected:
    Port(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {"port"}, std::move(meta)) {}

    HILTI_NODE_1(type::Port, UnqualifiedType, final);
};

} // namespace hilti::type
