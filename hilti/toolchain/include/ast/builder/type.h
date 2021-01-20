// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/id.h>

namespace hilti::builder {

inline Type typeByID(::hilti::ID id, Meta m = Meta()) { return hilti::type::UnresolvedID(std::move(id), std::move(m)); }

/**
 * Determines a common type for a list of expressions.
 *
 * @param e expressions
 * @return if *e* is non-empty and all expressions have the same type,
 * returns that type; otherwise returns ``type::Unknown``.
 */
Type typeOfExpressions(const std::vector<Expression>& e);

} // namespace hilti::builder
