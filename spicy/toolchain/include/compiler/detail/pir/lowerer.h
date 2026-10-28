// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/forward.h>

#include <spicy/ast/forward.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/pir.h>

namespace spicy::detail::pir {

/** Discovery output of public roots (functions/units). */
struct RootDiscovery {
    std::vector<hilti::Declaration*> roots;
    std::vector<hilti::declaration::Type*> unit_declarations;
    std::optional<UnsupportedFeature> unrepresented_content;
    std::vector<std::string> cxx_includes;                    /**< `%cxx-include` headers of all modules */
    std::vector<spicy::declaration::UnitHook*> unit_hooks;    /**< external unit hooks; applied to lowered units */
    std::vector<hilti::declaration::GlobalVariable*> globals; /**< module-level variables, all lowered */
    std::vector<std::pair<hilti::declaration::Function*, ir::InitPhase>> initializers; /**< in source order */
};

RootDiscovery discoverRoots(const hilti::ASTContext& ctx);

/**
 * Attempts to lower every discovered root into `package`, in order. Stops
 * and returns the first unsupported feature encountered, if any.
 *
 * Foreign declarations that only the target can implement are reported in `bindings`.
 *
 * If there are any unsupported features, the resulting `package` is invalid.
 */
std::optional<UnsupportedFeature> lowerRoots(const RootDiscovery& discovery,
                                             ir::Package& package,
                                             std::vector<TargetBinding>& bindings);

} // namespace spicy::detail::pir
