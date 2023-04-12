// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/library.h>

namespace hilti::ctor {

/**
 * AST node for a constructor of an instance of a library type. Because we
 * don't know more about the internal representation of the library type, we
 * represent the value through a ctor of another, known type. The code
 * generator must ensure that coercion operates correctly for the final C++
 * code.
 **/
class Library : public NodeBase, public hilti::trait::isCtor {
public:
    Library(Ctor ctor, Type lib_type, Meta m = Meta())
        : NodeBase({std::move(ctor), std::move(lib_type)}, std::move(m)) {}

    const auto& value() const { return child<Ctor>(0); }

    bool operator==(const Library& other) const { return value() == other.value() && type() == other.type(); }

    /** Implements `Ctor` interface. */
    const Type& type() const { return child<Type>(1); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return value().isConstant(); }
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
