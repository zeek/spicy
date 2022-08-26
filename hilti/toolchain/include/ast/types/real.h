// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a floating point type. */
class Real : public TypeBase {
public:
    Real(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Real& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }

    node::Properties properties() const override { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isSortable() const override { return true; }
};

} // namespace hilti::type
