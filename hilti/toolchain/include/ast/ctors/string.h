// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/string.h>

namespace hilti::ctor {

/** AST node for a `string` ctor. */
class String : public Ctor {
public:
    const auto& value() const { return _value; }
    auto isLiteral() const { return _is_literal; }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", _value}, {"is_literal", _is_literal}};
        return Ctor::properties() + p;
    }

    static auto create(ASTContext* ctx, std::string value, bool is_literal, const Meta& meta = {}) {
        return CtorPtr(new String(ctx, {QualifiedType::create(ctx, type::String::create(ctx, meta), Constness::Const)},
                                  std::move(value), is_literal, meta));
    }

protected:
    String(ASTContext* ctx, Nodes children, std::string value, bool is_literal, Meta meta)
        : Ctor(ctx, std::move(children), std::move(meta)), _value(std::move(value)), _is_literal(is_literal) {}

    HILTI_NODE(hilti, String)

private:
    std::string _value;
    bool _is_literal = false;
};

} // namespace hilti::ctor
