// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <ranges>
#include <string>
#include <utility>

#include <hilti/rt/types/regexp.h>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/types/regexp.h>

namespace hilti::ctor {

namespace regexp {
using Pattern = hilti::rt::regexp::Pattern;
using Patterns = hilti::rt::regexp::Patterns;
} // namespace regexp

/**
 * AST node for a regular expression ctor. A regular expression ctor stores one
 * or more individual patterns that will all be matched in parallel.
 */
class RegExp : public Ctor {
public:
    const auto& patterns() const { return _patterns; }
    auto attributes() const { return child<AttributeSet>(1); }

    /**
     * Returns true if this pattern does not need support for capturing groups.
     */
    bool isNoSub() const { return attributes()->find(hilti::attribute::kind::Nosub) != nullptr; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{
            {"pattern",
             util::join(_patterns | std::views::transform([](const auto& p) { return to_string(p); }), " | ")}};
        return Ctor::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, regexp::Patterns v, AttributeSet* attrs, const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<RegExp>(ctx,
                                 {QualifiedType::create(ctx, type::RegExp::create(ctx, meta), Constness::Const), attrs},
                                 std::move(v), meta);
    }

protected:
    RegExp(ASTContext* ctx, Nodes children, regexp::Patterns v, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), _patterns(std::move(v)) {}

    HILTI_NODE_1(ctor::RegExp, Ctor, final);

private:
    regexp::Patterns _patterns;
};

} // namespace hilti::ctor
