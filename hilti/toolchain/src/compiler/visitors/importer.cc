// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>

using namespace hilti;

namespace {

struct Visitor : public visitor::PreOrder<void, Visitor> {
    Visitor(Unit* unit) : unit(unit) {}
    std::set<context::ModuleIndex> imported;

    void operator()(const declaration::ImportedModule& m) {
        hilti::rt::filesystem::path path;

        if ( m.path().empty() ) {
            if ( auto x = unit->import(m.id(), m.extension(), m.scope(), m.searchDirectories()) )
                path = x->path;
            else
                logger().error(util::fmt("cannot import module '%s': %s", m.id(), x.error()), m);
        }
        else {
            if ( auto x = unit->import(m.path()) ) {
                if ( x->id != m.id() )
                    logger().error(util::fmt("unexpected module '%s' in %s", x->id, path), m);

                path = m.path();
            }
            else
                logger().error(util::fmt("cannot import module %s: %s", m.path(), x.error()), m);
        }

        imported.emplace(m.id(), path);
    }

    Unit* unit;
};

} // anonymous namespace


std::set<context::ModuleIndex> hilti::detail::importModules(const Node& root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/importer");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.imported;
}
