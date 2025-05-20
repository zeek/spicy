// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>

namespace hilti {

/** Base class for classes implementing constructor nodes. */
class Ctor : public Node {
public:
    ~Ctor() override;

    /** Returns the HILTI type of the constructor's value. */
    virtual QualifiedType* type() const = 0;

    /** Returns true for constructors creating a reference to another type. */
    virtual bool isReferenceCtor() const { return false; }

protected:
    Ctor(ASTContext* ctx, node::Tags node_tags, Nodes children, Meta meta)
        : Node::Node(ctx, node_tags, std::move(children), std::move(meta)) {}

    std::string _dump() const override;

    HILTI_NODE_0(Ctor, override);
};

} // namespace hilti
