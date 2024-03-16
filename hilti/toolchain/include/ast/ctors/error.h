// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/error.h>

namespace hilti::ctor {

/** AST node for a error ctor. */
class Error : public Ctor {
public:
    const auto& value() const { return _value; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"value", _value}};
        return Ctor::properties() + p;
    }

    static auto create(ASTContext* ctx, std::string v, const Meta& meta = {}) {
        return ctx->make<Error>(ctx, {QualifiedType::create(ctx, type::Error::create(ctx, meta), Constness::Const)},
                                std::move(v), meta);
    }

protected:
    Error(ASTContext* ctx, Nodes children, std::string v, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), _value(std::move(v)) {}

    HILTI_NODE_1(ctor::Error, Ctor, final);

private:
    std::string _value;
};

} // namespace hilti::ctor
