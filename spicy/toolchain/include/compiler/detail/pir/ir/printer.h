// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

/** Renders `package` deterministically. */
std::string print(const Package& package);

} // namespace spicy::detail::pir::ir
