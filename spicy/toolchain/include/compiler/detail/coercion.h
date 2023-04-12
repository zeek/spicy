// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/compiler/coercion.h>

#include <spicy/ast/aliases.h>

namespace spicy::detail {

/** Implements the corresponding functionality for the Spicy compiler plugin. */
std::optional<Ctor> coerceCtor(Ctor c, const Type& dst, bitmask<hilti::CoercionStyle> style);
/** Implements the corresponding functionality for the Spicy compiler plugin. */
std::optional<Type> coerceType(Type t, const Type& dst, bitmask<hilti::CoercionStyle> style);

} // namespace spicy::detail
