// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an `auto` type. */
class Auto : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, const Meta& m = Meta()) { return std::shared_ptr<Auto>(new Auto(ctx, m)); }

    std::string_view typeClass() const final { return "auto"; }

    bool isResolved(node::CycleDetector* cd) const final { return false; }

protected:
    Auto(ASTContext* ctx, const Meta& meta) : UnqualifiedType(ctx, {}, meta) {}


    HILTI_NODE(hilti, Auto);
};

} // namespace hilti::type
