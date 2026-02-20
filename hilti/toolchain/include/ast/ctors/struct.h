// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/struct.h>

namespace hilti::ctor {

namespace struct_ {

/** Base class for struct field nodes. */
class Field final : public Node {
public:
    ~Field() final;

    const auto& id() const { return _id; }
    auto expression() const { return child<Expression>(0); }

    node::Properties properties() const override {
        auto p = node::Properties{{"id", _id}};
        return Node::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, ID id, Expression* expr, Meta meta = {}) {
        return ctx->make<Field>(ctx, {expr}, std::move(id), std::move(meta));
    }

protected:
    Field(ASTContext* ctx, Nodes children, ID id, Meta meta = {})
        : Node(ctx, NodeTags, std::move(children), std::move(meta)), _id(std::move(id)) {}

    HILTI_NODE_0(ctor::struct_::Field, final);

private:
    ID _id;
};

using Fields = NodeVector<Field>;

} // namespace struct_

/** AST node for a `struct` ctor. */
class Struct : public Ctor, public node::WithUniqueID {
public:
    auto stype() const { return type()->type()->as<type::Struct>(); }

    /** Returns all fields that the constructors initialized. */
    auto fields() const { return children<struct_::Field>(1, {}); }

    /** Returns a field initialized by the constructor by its ID. */
    struct_::Field* field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f->id() == id )
                return f;
        }

        return nullptr;
    }

    /**
     * Remove a field of a given name if it exists.
     *
     * @param id field ID
     */
    void removeField(const ID& id) {
        if ( auto* f = field(id) )
            removeChild(f);
    }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, QualifiedType* t) {
        assert(t->type()->isA<type::Struct>());
        setChild(ctx, 0, t);
    }

    /** Implements the node interface. */
    node::Properties properties() const override {
        auto p = node::Properties{};
        return Ctor::properties() + node::WithUniqueID::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, const struct_::Fields& fields, QualifiedType* t, Meta meta = {}) {
        return ctx->make<Struct>(ctx, node::flatten(t, fields), std::move(meta));
    }

    static auto create(ASTContext* ctx, const struct_::Fields& fields, const Meta& meta = {}) {
        return ctx->make<Struct>(ctx, node::flatten(QualifiedType::createAuto(ctx, meta), fields), meta);
    }

protected:
    Struct(ASTContext* ctx, Nodes children, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)), WithUniqueID("struct") {
        assert(type()->type()->isA<type::Auto>() || type()->type()->isA<type::Struct>());
    }

    HILTI_NODE_1(ctor::Struct, Ctor, final);
};

} // namespace hilti::ctor
