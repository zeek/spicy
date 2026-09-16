// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ast-context.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>

#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>
#include <spicy/compiler/detail/pir/lowerer.h>
#include <spicy/compiler/detail/pir/passes/constant-fold.h>
#include <spicy/compiler/detail/pir/pir.h>

using namespace spicy;
using namespace spicy::detail;
using hilti::util::fmt;

pir::BuildResult pir::build(const hilti::ASTContext& ctx) {
    hilti::util::timing::Collector _("spicy/compiler/pir/build");

    auto roots = discoverRoots(ctx);
    HILTI_DEBUG(logging::debug::PIR, fmt("found %d root(s)", roots.size()));

    ir::Package package;
    {
        hilti::util::timing::Collector _("spicy/compiler/pir/build/lower");
        if ( auto feature = lowerRoots(roots, package) )
            return BuildOutcome(Unsupported{{*feature}});
    }

    HILTI_DEBUG(logging::debug::PIR,
                fmt("constructed %d function(s), %d instruction(s)",
                    package.functions().size(),
                    package.instructions().size()));

    std::vector<ir::Diagnostic> diags;
    {
        hilti::util::timing::Collector _("spicy/compiler/pir/build/verify");
        diags = ir::verify(package);
    }

    if ( ! diags.empty() )
        return BuildOutcome(Error{.package = std::move(package), .diagnostics = std::move(diags)});

    HILTI_DEBUG(logging::debug::PIR, "before constant folding:");
    HILTI_DEBUG(logging::debug::PIR, ir::print(package));

    bool changed = false;
    {
        hilti::util::timing::Collector _("spicy/compiler/pir/build/fold");
        for ( size_t i = 0; i < package.functions().size(); ++i )
            changed = passes::foldConstants(package, ir::FunctionId{static_cast<uint32_t>(i)}) || changed;
    }

    HILTI_DEBUG(logging::debug::PIR, fmt("constant folding changed the package: %s", changed ? "yes" : "no"));

    {
        hilti::util::timing::Collector _("spicy/compiler/pir/build/verify");
        diags = ir::verify(package);
    }

    if ( ! diags.empty() )
        return BuildOutcome(Error{.package = std::move(package), .diagnostics = std::move(diags)});

    HILTI_DEBUG(logging::debug::PIR, "after constant folding:");
    HILTI_DEBUG(logging::debug::PIR, ir::print(package));

    return BuildOutcome(Success{std::move(package)});
}
