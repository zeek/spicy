// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a null type. */
class Null : public TypeBase {
public:
    Null(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Null& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }

    node::Properties properties() const override { return node::Properties{}; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    HILTI_TYPE_VISITOR_IMPLEMENT
};

} // namespace hilti::type
