// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <vector>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>

#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/pir/pir.h>

using namespace spicy;
using namespace spicy::detail;

using hilti::util::fmt;

namespace {

// Read-only visitor determining the parser roots that PIR construction would
// start from.
struct VisitorRoots : public visitor::PreOrder {
    std::vector<ID> roots;

    void operator()(hilti::declaration::Type* n) final {
        auto* unit = n->type()->type()->tryAs<type::Unit>();
        if ( ! unit || n->type()->alias() )
            return;

        if ( unit->isPublic() )
            roots.emplace_back(unit->typeID());
    }
};

} // namespace

pir::BuildResult pir::build(const hilti::ASTContext& ctx) {
    hilti::util::timing::Collector _("spicy/compiler/pir/build");

    auto v = VisitorRoots();
    visitor::visit(v, ctx.root(), ".spicy");

    HILTI_DEBUG(logging::debug::PIR, fmt("found %d parser root(s)", v.roots.size()));
    for ( const auto& r : v.roots )
        HILTI_DEBUG(logging::debug::PIR, fmt("  %s", r));

    // Nothing is representable in PIR yet.
    return BuildOutcome(Unsupported{
        {{.feature = "parser IR construction", .reason = "not implemented yet", .location = hilti::location::None}}});
}
