// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

#include <spicy/ast/forward.h>

namespace spicy::type {

/** AST node for a Sink type. */
class Sink : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, const Meta& meta = {}) { return std::shared_ptr<Sink>(new Sink(ctx, meta)); }

    std::string_view typeClass() const final { return "sink"; }

    bool isAllocable() const final { return true; }

protected:
    Sink(ASTContext* ctx, const Meta& meta) : UnqualifiedType(ctx, {"sink"}, meta) {}

    HILTI_NODE(spicy, Sink)
};

} // namespace spicy::type
