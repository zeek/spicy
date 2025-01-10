// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/types/regexp.h>

namespace hilti::ctor {

/** AST node for a regular expression ctor. */
class RegExp : public Ctor {
public:
    const auto& value() const { return _value; }
    auto attributes() const { return child<AttributeSet>(1); }

    /**
     * Returns true if this pattern does not need support for capturing groups.
     */
    bool isNoSub() const { return attributes()->find(hilti::attribute::Kind::Nosub) != nullptr; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", util::join(_value, " | ")}};
        return Ctor::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, std::vector<std::string> v, AttributeSet* attrs, const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<RegExp>(ctx,
                                 {QualifiedType::create(ctx, type::RegExp::create(ctx, meta), Constness::Const), attrs},
                                 std::move(v), meta);
    }

protected:
    RegExp(ASTContext* ctx, Nodes children, std::vector<std::string> v, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), _value(std::move(v)) {}

    HILTI_NODE_1(ctor::RegExp, Ctor, final);

private:
    std::vector<std::string> _value;
};

} // namespace hilti::ctor
