// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

/** Renders `package` deterministically. */
std::string print(const Package& package);

/** Renders a type's canonical spelling, e.g. for use in diagnostics. Structural for unit/tuple types. */
std::string typeName(const Package& package, TypeId type_id);

} // namespace spicy::detail::pir::ir
