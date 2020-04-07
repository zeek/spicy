// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>
#include <hilti/base/logger.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;
using namespace hilti;

namespace {

struct Visitor : public hilti::visitor::PostOrder<void, Visitor> {
    explicit Visitor(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;
};

} // anonymous namespace

void spicy::detail::buildScopes(const std::vector<std::pair<ID, NodeRef>>& modules, hilti::Unit* unit) {
    util::timing::Collector _("spicy/compiler/scope-builder");

    for ( auto& [id, m] : modules ) {
        auto v = Visitor(unit);
        for ( auto i : v.walk(&*m) )
            v.dispatch(i);
    }
}
