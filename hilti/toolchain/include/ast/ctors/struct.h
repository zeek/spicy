// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

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
        return Node::properties() + p;
    }

    static auto create(ASTContext* ctx, ID id, const ExpressionPtr& expr, Meta meta = {}) {
        return std::shared_ptr<Field>(new Field(ctx, {expr}, std::move(id), std::move(meta)));
    }

protected:
    Field(ASTContext* ctx, Nodes children, ID id, Meta meta = {})
        : Node(ctx, std::move(children), std::move(meta)), _id(std::move(id)) {}

    HILTI_NODE(hilti, Field);

private:
    ID _id;
};

using FieldPtr = std::shared_ptr<Field>;
using Fields = std::vector<FieldPtr>;

} // namespace struct_

/** AST node for a `struct` ctor. */
class Struct : public Ctor, public node::WithUniqueID {
public:
    auto stype() const { return type()->type()->as<type::Struct>(); }

    /** Returns all fields that the constructors initialized. */
    auto fields() const { return children<struct_::Field>(1, {}); }

    /** Returns a field initialized by the constructor by its ID. */
    struct_::FieldPtr field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f->id() == id )
                return f;
        }

        return nullptr;
    }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }
    void setType(ASTContext* ctx, const QualifiedTypePtr& t) { setChild(ctx, 0, t); }

    /** Implements the node interface. */
    node::Properties properties() const override {
        auto p = node::Properties{};
        return Ctor::properties() + node::WithUniqueID::properties() + p;
    }

    static auto create(ASTContext* ctx, struct_::Fields fields, QualifiedTypePtr t, const Meta& meta = {}) {
        return std::shared_ptr<Struct>(new Struct(ctx, node::flatten(std::move(t), std::move(fields)), meta));
    }

    static auto create(ASTContext* ctx, struct_::Fields fields, const Meta& meta = {}) {
        return std::shared_ptr<Struct>(
            new Struct(ctx, node::flatten(QualifiedType::createAuto(ctx, meta), std::move(fields)), meta));
    }

protected:
    Struct(ASTContext* ctx, Nodes children, Meta meta)
        : Ctor(ctx, std::move(children), std::move(meta)), WithUniqueID("struct") {}

    HILTI_NODE(hilti, Struct)
};

} // namespace hilti::ctor
