// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/types/enum.h>

namespace hilti {

namespace ctor {

/** AST node for an enum constructor. */
class Enum : public NodeBase, public hilti::trait::isCtor {
public:
    Enum(type::enum_::Label v, type::Enum t, Meta m = Meta()) : NodeBase({std::move(v), std::move(t)}, std::move(m)) {}
    Enum(type::enum_::Label v, NodeRef td, Meta m = Meta())
        : NodeBase({std::move(v), node::none}, std::move(m)), _type_decl(std::move(td)) {}

    const auto& value() const { return childs()[0].as<type::enum_::Label>(); }

    bool operator==(const Enum& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    auto type() const {
        return type::effectiveType(_type_decl ? type::effectiveType((*_type_decl)->as<declaration::Type>().type()) :
                                                childs()[1].as<type::Enum>());
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

private:
    std::optional<NodeRef> _type_decl;
};

} // namespace ctor
} // namespace hilti
