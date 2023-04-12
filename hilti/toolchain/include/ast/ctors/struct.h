// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>
#include <vector>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/struct.h>

namespace hilti::ctor {

namespace struct_ {
/** AST node for a struct field constructor. */
class Field : public NodeBase {
public:
    Field(ID id, Expression e, Meta m = Meta()) : NodeBase(nodes(std::move(id), std::move(e)), std::move(m)) {}
    Field(Meta m = Meta()) : NodeBase(nodes(node::none, node::none), std::move(m)) {}

    const auto& id() const { return child<ID>(0); }
    const auto& expression() const { return child<Expression>(1); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Field& other) const { return id() == other.id() && expression() == other.expression(); }
};

inline Node to_node(Field f) { return Node(std::move(f)); }
} // namespace struct_

/** AST node for a struct constructor. */
class Struct : public NodeBase, public hilti::trait::isCtor {
public:
    Struct(std::vector<struct_::Field> f, Meta m = Meta()) : NodeBase(nodes(type::auto_, std::move(f)), std::move(m)) {}
    Struct(std::vector<struct_::Field> f, Type t, Meta m = Meta())
        : NodeBase(nodes(std::move(t), std::move(f)), std::move(m)) {}

    /** Returns all fields that the constructors initialized. */
    auto fields() const { return children<struct_::Field>(1, -1); }

    auto stype() const { return child<type::Struct>(0); }

    /** Returns a field initialized by the constructor by its ID. */
    hilti::optional_ref<const struct_::Field> field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                return f;
        }

        return {};
    }

    void setType(const Type& t) { children()[0] = t; }

    bool operator==(const Struct& other) const { return fields() == other.fields(); }

    /** Implements `Ctor` interface. */
    const auto& type() const { return child<Type>(0); }

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

} // namespace hilti::ctor
