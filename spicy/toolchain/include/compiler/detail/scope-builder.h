// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/compiler/unit.h>

#include <spicy/ast/forward.h>

namespace spicy::detail::scope_builder {

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void build(Builder* builder, const ASTRootPtr& root);

} // namespace spicy::detail::scope_builder
