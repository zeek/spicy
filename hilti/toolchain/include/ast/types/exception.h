// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a `exception` type. */
class Exception : public UnqualifiedType {
public:
    auto baseType() const { return child<UnqualifiedType>(0); }

    std::string_view typeClass() const final { return "exception"; }

    bool isAllocable() const final { return true; }
    bool isNameType() const final { return true; }

    static auto create(ASTContext* ctx, const UnqualifiedTypePtr& base, Meta meta = {}) {
        return std::shared_ptr<Exception>(new Exception(ctx, {base}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, const Meta& meta = {}) { return create(ctx, nullptr, meta); }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return std::shared_ptr<Exception>(new Exception(ctx, Wildcard(), {type::Unknown::create(ctx, m)}, m));
    }

protected:
    Exception(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    Exception(ASTContext* ctx, Wildcard _, const Nodes& children, const Meta& meta)
        : UnqualifiedType(ctx, Wildcard(), {"exception(*)"}, children, meta) {}

    bool isResolved(node::CycleDetector* cd) const final { return baseType() ? baseType()->isResolved(cd) : true; }

    HILTI_NODE(hilti, Exception)
};

} // namespace hilti::type
