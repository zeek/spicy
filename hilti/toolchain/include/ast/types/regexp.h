// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a regular expression type. */
class RegExp : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "regexp"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) {
        return std::shared_ptr<RegExp>(new RegExp(ctx, std::move(meta)));
    }

protected:
    RegExp(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, {"regexp"}, std::move(meta)) {}

    HILTI_NODE(hilti, RegExp)
};

} // namespace hilti::type
