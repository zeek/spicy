// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <vector>

#include <spicy/compiler/detail/pir/ir/diagnostic.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

/** Returns all structural and typing errors in `package`. */
std::vector<Diagnostic> verify(const Package& package);

} // namespace spicy::detail::pir::ir
