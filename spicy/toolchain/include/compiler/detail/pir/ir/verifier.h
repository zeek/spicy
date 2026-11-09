// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <vector>

#include <spicy/compiler/detail/pir/ir/internal-error.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

/** Returns internal compiler errors for invalid structure or types in `package`. */
std::vector<InternalError> verify(const Package& package);

} // namespace spicy::detail::pir::ir
