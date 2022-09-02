// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a void type. */
class Void : public TypeBase {
public:
    bool operator==(const Void& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }

    node::Properties properties() const override { return node::Properties{}; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    /**
     * Wrapper around constructor so that we can make it private. Don't use
     * this, use the singleton `type::void_` instead.
     */
    static Void create(Meta m = Meta()) { return Void(std::move(m)); }

    HILTI_TYPE_VISITOR_IMPLEMENT

private:
    Void(Meta m = Meta()) : TypeBase(std::move(m)) {}
};

/** Singleton. */
static const Type void_ = Void::create(Location("<singleton>"));
} // namespace hilti::type
