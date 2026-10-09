// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <string>
#include <variant>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/integer.h>
#include <hilti/base/util.h>

#include <spicy/ast/declarations/hook.h>
#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/pir/builder.h>
#include <spicy/compiler/detail/pir/lowerer.h>

using hilti::util::fmt;

namespace spicy::detail::pir {

namespace {

UnsupportedFeature unsupported(const std::string& feature, std::string reason, const hilti::Location& loc) {
    return UnsupportedFeature{.feature = feature, .reason = std::move(reason), .location = loc};
}

// Collects candidate roots for lowering PIR, as well as marking known
// unsupported constructs.
struct VisitorRoots : public visitor::PreOrder {
    std::vector<hilti::Declaration*> roots;
    std::vector<hilti::declaration::Type*> unit_declarations;
    std::vector<hilti::ast::TypeIndex> units_with_external_hooks;
    std::optional<UnsupportedFeature> unrepresented_content;

    static bool skipsImplementation(hilti::Declaration* n) {
        auto* m = n->parent<hilti::declaration::Module>();
        return m && m->skipImplementation();
    }

    void operator()(hilti::declaration::Function* n) final {
        if ( n->isPublic() && ! skipsImplementation(n) )
            roots.push_back(n);
    }

    void operator()(hilti::declaration::Type* n) final {
        auto* unit = n->type()->type()->tryAs<type::Unit>();
        if ( ! unit ) {
            if ( n->isPublic() && ! skipsImplementation(n) && ! unrepresented_content )
                unrepresented_content = unsupported(fmt("public type '%s'", std::string(n->id())),
                                                    "only parser unit types are supported yet",
                                                    n->meta().location());
            return;
        }

        // Aliases may have different linkage than what they alias.
        bool is_public = n->type()->alias() ? n->isPublic() : unit->isPublic();

        if ( ! n->type()->alias() && ! skipsImplementation(n) )
            unit_declarations.push_back(n);

        if ( is_public && ! skipsImplementation(n) )
            roots.push_back(n);
    }

    // External hooks from the unit itself
    void operator()(spicy::declaration::UnitHook* n) final {
        if ( auto index = n->hook()->unitTypeIndex() )
            units_with_external_hooks.push_back(index);
    }

    void operator()(hilti::declaration::GlobalVariable* n) final {
        if ( ! skipsImplementation(n) && ! unrepresented_content )
            unrepresented_content = unsupported("global variable",
                                                "global variables and their initialization are not supported yet",
                                                n->meta().location());
    }

    void operator()(hilti::declaration::Constant* n) final {
        if ( n->isPublic() && ! skipsImplementation(n) && ! unrepresented_content )
            unrepresented_content = unsupported(fmt("public constant '%s'", std::string(n->id())),
                                                "constants are not supported yet",
                                                n->meta().location());
    }
};

} // namespace

RootDiscovery discoverRoots(const hilti::ASTContext& ctx) {
    auto v = VisitorRoots();
    visitor::visit(v, ctx.root(), ".spicy");
    return RootDiscovery{.roots = std::move(v.roots),
                         .unit_declarations = std::move(v.unit_declarations),
                         .units_with_external_hooks = std::move(v.units_with_external_hooks),
                         .unrepresented_content = std::move(v.unrepresented_content)};
}

std::optional<UnsupportedFeature> lowerRoots(const RootDiscovery& discovery, ir::Package& package) {
    // If discovery doesn't support something, lowering also won't.
    if ( discovery.unrepresented_content )
        return discovery.unrepresented_content;

    std::vector<hilti::declaration::Type*> unit_roots;
    for ( auto* decl : discovery.roots ) {
        if ( auto* fn_decl = decl->tryAs<hilti::declaration::Function>() ) {
            if ( auto feature = buildFunction(fn_decl, package) )
                return feature;

            continue;
        }

        if ( auto* type_decl = decl->tryAs<hilti::declaration::Type>() ) {
            if ( type_decl->type()->alias() )
                return unsupported(fmt("public unit alias '%s'", std::string(type_decl->id())),
                                   "public unit aliases are not supported yet",
                                   type_decl->meta().location());

            unit_roots.push_back(type_decl);

            continue;
        }
    }

    if ( auto feature =
             buildUnits(unit_roots, discovery.unit_declarations, discovery.units_with_external_hooks, package) )
        return feature;

    return std::nullopt;
}

} // namespace spicy::detail::pir
