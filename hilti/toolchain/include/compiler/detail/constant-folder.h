// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/3rdparty/ArticleEnumClass-v2/EnumClass.h>

#include <hilti/ast/forward.h>
#include <hilti/base/result.h>

namespace hilti::detail::constant_folder {

enum class Style { FoldFeatureConstants = (1U << 0U), InlineAllConstants = (1U << 1U), Default = 0U };

/**
 * Folds an expression into a constant value if that's possible. Note that the
 * current implementation is very, very basic, and covers just a few cases. If
 * the function returns an error, that does not necessarily mean that the
 * expression is not representing a constant value, but only that we aren't
 * able to compute it.
 */
Result<Ctor*> foldExpression(Builder* builder, Expression* expr, bitmask<Style> style = Style::Default);

bool fold(Builder* builder, Node* node, bitmask<Style> style = Style::Default);

} // namespace hilti::detail::constant_folder


enableEnumClassBitmask(hilti::detail::constant_folder::Style); // must be in global scope
