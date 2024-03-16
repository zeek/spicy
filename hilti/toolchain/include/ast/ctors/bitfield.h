// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/bitfield.h>

namespace hilti::ctor {

class Bitfield;

namespace bitfield {

/** AST node for a bitfield element. */
class BitRange final : public Node {
public:
    ~BitRange() final;

    const auto& id() const { return _id; }
    auto expression() const { return child<Expression>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{
            {"id", _id},
        };

        return Node::properties() + p;
    }

    static auto create(ASTContext* ctx, const ID& id, Expression* expr, Meta meta = Meta()) {
        return ctx->make<BitRange>(ctx, {expr}, id, std::move(meta));
    }

protected:
    friend class type::Bitfield;

    BitRange(ASTContext* ctx, Nodes children, ID id, Meta meta = Meta())
        : Node(ctx, NodeTags, std::move(children), std::move(meta)), _id(std::move(id)) {}

    HILTI_NODE_0(ctor::bitfield::BitRange, final);

private:
    ID _id;
};

using BitRanges = NodeVector<BitRange>;

} // namespace bitfield

/** AST node for a `bitfield` type. */
class Bitfield : public Ctor {
public:
    /** Returns all bits that the constructor initializes. */
    auto bits() const { return children<bitfield::BitRange>(1, {}); }

    /** Returns the underlying bitfield type. */
    auto btype() const { return type()->type()->as<type::Bitfield>(); }

    /** Returns a field initialized by the constructor by its ID. */
    bitfield::BitRange* bits(const ID& id) const {
        for ( const auto& b : bits() ) {
            if ( b->id() == id )
                return b;
        }

        return {};
    }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const ctor::bitfield::BitRanges& bits, QualifiedType* type,
                       const Meta& m = Meta()) {
        return ctx->make<Bitfield>(ctx, node::flatten(type, bits), m);
    }

protected:
    Bitfield(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Bitfield, Ctor, final);
};

} // namespace hilti::ctor
