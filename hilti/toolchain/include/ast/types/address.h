// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an `addr` type. */
class Address : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, const Meta& m = Meta()) {
        return std::shared_ptr<Address>(new Address(ctx, m));
    }

    std::string_view typeClass() const final { return "address"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

protected:
    Address(ASTContext* ctx, const Meta& meta) : UnqualifiedType(ctx, {"address"}, meta) {}

    HILTI_NODE(hilti, Address);
};

} // namespace hilti::type
