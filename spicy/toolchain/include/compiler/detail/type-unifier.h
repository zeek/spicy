// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/compiler/type-unifier.h>

#include <spicy/ast/forward.h>

namespace spicy::type_unifier::detail {

/** Implements the corresponding functionality for Spicy compiler plugin. */
bool unifyType(hilti::type_unifier::Unifier* unifier, UnqualifiedType* t);

} // namespace spicy::type_unifier::detail
