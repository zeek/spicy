// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/autogen/config.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/plugin.h>

using namespace hilti;
using namespace hilti::detail;

PluginRegistry::PluginRegistry() = default; // Neded here to allow PluginRegistry to be forward declared.

Result<Plugin> PluginRegistry::pluginForExtension(std::filesystem::path ext) const {
    auto p = std::find_if(_plugins.begin(), _plugins.end(), [&](auto& p) { return p.extension == ext; });
    if ( p != _plugins.end() )
        return *p;

    return result::Error(util::fmt("no plugin registered for extension %s", ext));
}

PluginRegistry& plugin::registry() {
    static PluginRegistry singleton;
    return singleton;
}

// Always-on default plugin with HILTI functionality.
static Plugin hilti_plugin() {
    return Plugin{
        .component = "HILTI",
        .extension = ".hlt",
        .cxx_includes = {"hilti/rt/libhilti.h"},

        .library_paths =
            [](const std::shared_ptr<hilti::Context>& ctx) { return hilti::configuration().hilti_library_paths; },

        .parse = [](std::istream& in, const std::filesystem::path& path) { return parseSource(in, path); },

        .coerce_ctor = [](Ctor c, const Type& dst,
                          bitmask<CoercionStyle> style) { return detail::coerceCtor(std::move(c), dst, style); },

        .coerce_type = [](Type t, const Type& dst,
                          bitmask<CoercionStyle> style) { return detail::coerceType(std::move(t), dst, style); },

        .build_scopes = [](const std::shared_ptr<hilti::Context>& ctx, const std::vector<std::pair<ID, NodeRef>>& m,
                           Unit* u) { buildScopes(m, u); },

        .resolve_ids = [](const std::shared_ptr<hilti::Context>& ctx, Node* n, Unit* u) { return resolveIDs(n, u); },

        .resolve_operators = [](const std::shared_ptr<hilti::Context>& ctx, Node* n,
                                Unit* u) { return resolveOperators(n, u); },

        .apply_coercions = [](const std::shared_ptr<hilti::Context>& ctx, Node* n,
                              Unit* u) { return applyCoercions(n, u); },

        .pre_validate = {},

        .post_validate = [](const std::shared_ptr<hilti::Context>& ctx, Node* n, Unit* u) { validateAST(n); },

        .transform = {},
    };
}

static plugin::Register _(hilti_plugin());
