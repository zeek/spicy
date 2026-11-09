// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <vector>

#include <spicy/compiler/detail/pir/ir/diagnostic.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::analyses {

/**
 * Warns about unused fields of private units. A field counts as used if code addresses it or uses its parsed value
 * beyond storing it in the unit (for example, as `$$` in a hook). Passing the unit to foreign code, even inside a
 * tuple or container, counts as using all its fields. Public units are exempt because the host may read them.
 *
 * @param package a verified package
 * @return one `unused-field` warning per unused field, in package order
 */
std::vector<ir::Diagnostic> checkUnusedFields(const ir::Package& package);

} // namespace spicy::detail::pir::analyses
