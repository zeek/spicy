// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/declaration.h>

#include <spicy/ast/declarations/hook.h>

namespace spicy::declaration {

/** AST node for a declaration of an external (i.e., module-level) unit hook. */
class UnitHook : public Declaration {
public:
    auto hook() const { return child<declaration::Hook>(0); }

    std::string_view displayName() const final { return "unit hook"; }

    static auto create(ASTContext* ctx, const ID& id, declaration::Hook* hook, Meta meta = {}) {
        auto h = ctx->make<UnitHook>(ctx, {hook}, id, std::move(meta));
        h->hook()->setID(id);
        return h;
    }

protected:
    UnitHook(ASTContext* ctx, Nodes children, ID id, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), hilti::declaration::Linkage::Private,
                      std::move(meta)) {}

    SPICY_NODE_1(declaration::UnitHook, Declaration, final);
};

} // namespace spicy::declaration
