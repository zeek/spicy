// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/builder/node-factory.h>

#include <spicy/ast/all.h>

namespace spicy::builder {

/** Base class making the auto-generated node factory methods available. */
class NodeFactory {
public:
    /**
     * Constructor.
     *
     * @param context AST context to use for creating nodes.
     */
    NodeFactory(ASTContext* context) : _context(context) {}

    /** Returns the AST context in use for creating nodes. */
    ASTContext* context() const { return _context; }

private:
    ASTContext* _context;

public:
#include <spicy/ast/builder/autogen/__node-factory.h>
};

} // namespace spicy::builder
