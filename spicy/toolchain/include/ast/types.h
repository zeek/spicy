// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/type.h>

namespace spicy::type {

// Returns whether the passed type supports parsing literals.
bool supportsLiterals(const hilti::Type& t);

} // namespace spicy::type
