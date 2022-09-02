// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace spicy::type {

/** AST node for a Sink type. */
class Sink : public hilti::TypeBase {
public:
    Sink(hilti::Meta m = hilti::Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Sink& /* other */) const { return true; }

    bool isEqual(const hilti::Type& other) const override { return hilti::node::isEqual(this, other); }
    bool _isResolved(hilti::type::ResolvedState* rstate) const override { return true; }
    hilti::node::Properties properties() const override { return hilti::node::Properties{}; }

    bool _isAllocable() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    HILTI_TYPE_VISITOR_IMPLEMENT
};

} // namespace spicy::type
