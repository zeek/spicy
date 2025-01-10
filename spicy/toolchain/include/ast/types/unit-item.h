// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/node.h>

namespace spicy::type::unit {

/** Base class for all unit items. */
class Item : public hilti::Declaration {
public:
    /** Returns the type of the parsed unit item. */
    virtual QualifiedType* itemType() const = 0;

    /** Returns true if the item's type has been resolved. */
    virtual bool isResolved(hilti::node::CycleDetector* cd = nullptr) const = 0;

protected:
    Item(ASTContext* ctx, node::Tags node_tags, Nodes children, ID id, Meta meta)
        : hilti::Declaration(ctx, node_tags, std::move(children), std::move(id), {}, std::move(meta)) {}

    SPICY_NODE_1(type::unit::Item, Declaration, override);
};

} // namespace spicy::type::unit
