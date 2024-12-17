// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/struct.h>
#include <hilti/ast/types/bool.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/types/unit.h>

namespace spicy::ctor {

namespace unit {
/**
 * AST node for a unit field constructor (which is just the same as a struct
 * field constructor).
 */
using Field = hilti::ctor::struct_::Field;
using Fields = hilti::ctor::struct_::Fields;
} // namespace unit

/** AST node for a unit constructor. */
class Unit : public Ctor {
public:
    /** Returns all fields that the constructor initializes. */
    auto fields() const { return children<unit::Field>(1, {}); }

    /*** Returns the unit type the constructor is producing. */
    auto utype() const { return child<type::Unit>(0); }

    /** Returns a field initialized by the constructor through its ID. */
    unit::Field* field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f->id() == id )
                return f;
        }

        return {};
    }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    static auto create(ASTContext* ctx, ctor::unit::Fields fields, Meta meta = {}) {
        auto auto_ = QualifiedType::create(ctx, hilti::type::Auto::create(ctx), hilti::Constness::Const, meta);
        return ctx->make<Unit>(ctx, node::flatten(auto_, std::move(fields)), std::move(meta));
    }

    static auto create(ASTContext* ctx, ctor::unit::Fields fields, QualifiedType* t, Meta meta = {}) {
        return ctx->make<Unit>(ctx, node::flatten(t, std::move(fields)), std::move(meta));
    }

protected:
    Unit(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    SPICY_NODE_1(ctor::Unit, Ctor, final);
};


} // namespace spicy::ctor
