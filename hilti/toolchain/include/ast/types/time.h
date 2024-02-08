// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `time` type. */
class Time : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "time"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) {
        return std::shared_ptr<Time>(new Time(ctx, std::move(meta)));
    }

protected:
    Time(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, {"time"}, std::move(meta)) {}

    HILTI_NODE(hilti, Time)
};

} // namespace hilti::type
