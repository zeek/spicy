// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <vector>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/type.h>

#include <spicy/compiler/detail/pir/lowerer.h>

namespace spicy::detail::pir {

/** Constructs PIR for a supported source declaration. Source pointers remain local to construction. */
std::optional<UnsupportedFeature> buildFunction(hilti::declaration::Function* decl, ir::Package& package);
std::optional<UnsupportedFeature> buildUnits(const std::vector<hilti::declaration::Type*>& roots,
                                             const std::vector<hilti::declaration::Type*>& unit_declarations,
                                             const std::vector<hilti::ast::TypeIndex>& units_with_external_hooks,
                                             ir::Package& package);

} // namespace spicy::detail::pir
