// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/ast/forward.h>

namespace spicy::detail::validator {

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void validatePre(Builder* builder, const ASTRootPtr& root);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void validatePost(Builder* builder, const ASTRootPtr& root);

} // namespace spicy::detail::validator
