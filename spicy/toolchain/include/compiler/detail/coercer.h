// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/compiler/coercer.h>

#include <spicy/ast/forward.h>

namespace spicy::detail::coercer {

/** Implements the corresponding functionality for the Spicy compiler plugin. */
Ctor* coerceCtor(Builder* builder, Ctor* c, QualifiedType* dst, bitmask<hilti::CoercionStyle> style);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
QualifiedType* coerceType(Builder* builder, QualifiedType* t, QualifiedType* dst, bitmask<hilti::CoercionStyle> style);

} // namespace spicy::detail::coercer
