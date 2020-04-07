// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/struct.h>

namespace hilti {
namespace ctor {

namespace struct_ {
/** A struct field initialization in the form of key/value. */
using Field = std::pair<ID, Expression>;
} // namespace struct_

/** AST node for a struct constructor. */
class Struct : public NodeBase, public hilti::trait::isCtor {
public:
    Struct(std::vector<struct_::Field> f, Meta m = Meta())
        : NodeBase(nodes(type::unknown, std::move(f)), std::move(m)) {}
    Struct(std::vector<struct_::Field> f, Type t, Meta m = Meta())
        : NodeBase(nodes(std::move(t), std::move(f)), std::move(m)) {}

    /** Returns all field IDs that the constructors initialized. */
    auto ids() const { return childsOfType<ID>(); }

    /** Returns all field values that the constructors initializes. */
    auto values() const { return childsOfType<Expression>(); }

    /** Returns all fields that the constructors initialized. */
    auto fields() const { return util::zip2(ids(), values()); }

    /** Returns a field initialized by the constructor by its ID. */
    std::optional<struct_::Field> field(const ID& id) const {
        for ( auto f : fields() ) {
            if ( f.first == id )
                return f;
        }

        return {};
    }

    bool operator==(const Struct& other) const { return ids() == other.ids() && values() == other.values(); }

    /** Implements `Ctor` interface. */
    Type type() const {
        if ( auto t = childs()[0].as<Type>(); ! t.isA<type::Unknown>() )
            return type::effectiveType(t);

        auto f = util::transform(fields(), [](auto& x) {
            return type::struct_::Field(x.first, x.second.type(), {}, x.first.meta());
        });
        return type::Struct(f, meta());
    }

    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace ctor
} // namespace hilti
