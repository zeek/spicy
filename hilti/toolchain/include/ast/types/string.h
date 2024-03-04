// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `string` type. */
class String : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "string"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) {
        return std::shared_ptr<String>(new String(ctx, std::move(meta)));
    }

protected:
    String(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, {"string"}, std::move(meta)) {}

    HILTI_NODE(hilti, String)
};

} // namespace hilti::type
