// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/visitor.h>

#include <spicy/ast/visitor-dispatcher.h>

namespace spicy::visitor {

using hilti::visitor::dispatch;
using hilti::visitor::range;
using hilti::visitor::visit;

/**
 * Visitor performing a pre-order iteration over a Spicy AST.
 */
using PreOrder = hilti::visitor::Visitor<hilti::visitor::Order::Pre, visitor::Dispatcher>;

/**
 * Mutating visitor performing a pre-order iteration over a Spicy AST.
 */
using MutatingPreOrder = hilti::visitor::MutatingVisitor<hilti::visitor::Order::Pre, visitor::Dispatcher, Builder>;


/**
 * Visitor performing a post-order iteration over a Spicy AST.
 */
using PostOrder = hilti::visitor::Visitor<hilti::visitor::Order::Post, visitor::Dispatcher>;

/**
 * Mutating visitor performing a post-order iteration over a Spicy AST.
 */
using MutatingPostOrder = hilti::visitor::MutatingVisitor<hilti::visitor::Order::Post, visitor::Dispatcher, Builder>;

} // namespace spicy::visitor
