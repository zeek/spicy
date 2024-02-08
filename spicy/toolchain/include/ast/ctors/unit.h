// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
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
using FieldPtr = hilti::ctor::struct_::FieldPtr;
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
    unit::FieldPtr field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f->id() == id )
                return f;
        }

        return {};
    }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    void setType(ASTContext* ctx, QualifiedTypePtr t) { setChild(ctx, 0, std::move(t)); }

    static auto create(ASTContext* ctx, ctor::unit::Fields fields, const Meta& meta = {}) {
        auto auto_ = QualifiedType::create(ctx, hilti::type::Auto::create(ctx), hilti::Constness::Const, meta);
        return std::shared_ptr<Unit>(new Unit(ctx, node::flatten(std::move(auto_), std::move(fields)), meta));
    }

    static auto create(ASTContext* ctx, ctor::unit::Fields fields, QualifiedTypePtr t, const Meta& meta = {}) {
        return std::shared_ptr<Unit>(new Unit(ctx, node::flatten(std::move(t), std::move(fields)), meta));
    }

protected:
    Unit(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Unit)
};


} // namespace spicy::ctor
