// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/**
 * AST node for a type that's only used for documentation purposes. This type
 * allows to carry a textual description of a type over into auto-generated
 * documentation. If it's used anywhere else, it'll cause trouble.
 */
class DocOnly : public UnqualifiedType {
public:
    const auto& description() const { return _description; }

    static auto create(ASTContext* ctx, const std::string& description, Meta meta = {}) {
        // Note: We allow (i.e., must support) `ctx` being null.
        return ctx->make<DocOnly>(ctx, description, std::move(meta));
    }

    std::string_view typeClass() const final { return "doc-only"; }

protected:
    DocOnly(ASTContext* ctx, std::string description, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {"doc-only"}, std::move(meta)), _description(std::move(description)) {}

    HILTI_NODE_1(type::DocOnly, UnqualifiedType, final);

private:
    std::string _description;
};

} // namespace hilti::type
