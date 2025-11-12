// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>

namespace hilti {

/** Base class for function nodes. */
class Function : public Node {
public:
    const auto& id() const { return _id; }
    auto type() const { return child<QualifiedType>(0); }
    auto ftype() const { return child<QualifiedType>(0)->type()->as<type::Function>(); }
    auto body() const { return child<statement::Block>(1); }
    auto attributes() const { return child<AttributeSet>(2); }
    auto isStatic() const { return attributes()->find(hilti::attribute::kind::Static) != nullptr; }

    void setBody(ASTContext* ctx, statement::Block* b) { setChild(ctx, 1, b); }
    void setID(ID id) { _id = std::move(id); }
    void setResultType(ASTContext* ctx, QualifiedType* t) { ftype()->setResultType(ctx, t); }

    node::Properties properties() const override {
        auto p = node::Properties{{"id", _id}};
        return Node::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, const ID& id, type::Function* ftype, statement::Block* body,
                       AttributeSet* attrs = nullptr, const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Function>(ctx, {QualifiedType::create(ctx, ftype, Constness::Const, meta), body, attrs}, id,
                                   meta);
    }

protected:
    Function(ASTContext* ctx, Nodes children, ID id, Meta meta = {})
        : Node(ctx, NodeTags, std::move(children), std::move(meta)), _id(std::move(id)) {}

    std::string _dump() const override;

    HILTI_NODE_0(Function, final);

private:
    ID _id;
};

} // namespace hilti
