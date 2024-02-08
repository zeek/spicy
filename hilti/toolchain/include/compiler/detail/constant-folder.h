// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/base/result.h>

namespace hilti::detail::constant_folder {

/**
 * Folds an expression into a constant value if that's possible. Note that the
 * current implementation is very, very basic, and covers just a few cases. If
 * the function returns an error, that does not necessarily mean that the
 * expression is not represeneting a constant value, but only that we aren't
 * able to compute it.
 */
Result<CtorPtr> fold(Builder* builder, const ExpressionPtr& expr);

} // namespace hilti::detail::constant_folder
