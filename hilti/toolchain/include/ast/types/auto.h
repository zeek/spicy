// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an "auto" type. */
class Auto : public TypeBase {
public:
    bool operator==(const Auto& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return false; }
    node::Properties properties() const override { return node::Properties{}; }

    /**
     * Wrapper around constructor so that we can make it private. Don't use
     * this, use the singleton `type::auto_` instead.
     */
    static Auto create(Meta m = Meta()) { return Auto(std::move(m)); }

    bool _isAllocable() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    HILTI_TYPE_VISITOR_IMPLEMENT

private:
    Auto(Meta m = Meta()) : TypeBase(std::move(m)) {}
};

/** Singleton. */
static const Type auto_ = Auto::create(Location("<singleton>"));

} // namespace hilti::type
