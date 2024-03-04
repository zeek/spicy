// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `bool` type. */
class Bool : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, const Meta& meta = {}) { return std::shared_ptr<Bool>(new Bool(ctx, meta)); }

    std::string_view typeClass() const final { return "bool"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

protected:
    Bool(ASTContext* ctx, const Meta& meta) : UnqualifiedType(ctx, {"bool"}, meta) {}

    HILTI_NODE(hilti, Bool)
};

} // namespace hilti::type
