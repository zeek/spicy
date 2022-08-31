// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a string type. */
class String : public TypeBase {
public:
    String(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const String& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    node::Properties properties() const override { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isSortable() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    void dispatch(type::Visitor& v, type::Visitor::position_t& p) const override { v(*this, p); }
};

} // namespace hilti::type
