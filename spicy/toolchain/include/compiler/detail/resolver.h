// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/ast/forward.h>

namespace spicy::detail::resolver {

/** Implements the corresponding functionality for the Spicy compiler plugin. */
bool resolve(Builder* builder, const NodePtr& root);

} // namespace spicy::detail::resolver
