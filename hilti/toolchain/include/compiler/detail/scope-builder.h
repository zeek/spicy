// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/compiler/unit.h>

namespace hilti::detail::scope_builder {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
void build(Builder* builder, const ASTRootPtr& root);

} // namespace hilti::detail::scope_builder
