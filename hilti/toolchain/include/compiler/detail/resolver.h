// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/base/result.h>

namespace hilti::detail::resolver {

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool resolve(Builder* builder, const NodePtr& root);

} // namespace hilti::detail::resolver
