// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/base/result.h>

namespace hilti::detail::resolver {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool resolve(Builder* builder, Node* node);

} // namespace hilti::detail::resolver
