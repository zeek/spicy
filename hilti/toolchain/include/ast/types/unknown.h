// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an unknown place-holder type. */
class Unknown : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "unknown"; }

    static auto create(ASTContext* ctx, Meta meta = {}) {
        return std::shared_ptr<Unknown>(new Unknown(ctx, std::move(meta)));
    }

protected:
    Unknown(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, {type::NeverMatch()}, std::move(meta)) {}

    HILTI_NODE(hilti, Unknown)
};

} // namespace hilti::type
