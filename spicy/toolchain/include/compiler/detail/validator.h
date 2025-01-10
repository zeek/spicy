// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/ast/forward.h>

namespace spicy::detail::validator {

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void validatePre(Builder* builder, hilti::ASTRoot* root);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void validatePost(Builder* builder, hilti::ASTRoot* root);

} // namespace spicy::detail::validator
