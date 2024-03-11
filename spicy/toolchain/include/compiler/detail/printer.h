// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>

#include <hilti/compiler/printer.h>

#include <spicy/ast/forward.h>

namespace spicy::detail::printer {

/**
 * Prints out AST nodes as Spicy source code. This only prints nodes for which
 * we have a Spicy-side source code printer available. Returns false for those
 * where we don't, in which case the caller should fall back on HILTI-side node
 * printing.
 */
bool print(hilti::printer::Stream& stream, Node* root);

} // namespace spicy::detail::printer
