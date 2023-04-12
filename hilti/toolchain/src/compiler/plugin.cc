// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/plugin.h"

#include <hilti/autogen/config.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;
using namespace hilti::detail;

PluginRegistry::PluginRegistry() = default; // Needed here to allow PluginRegistry to be forward declared.

Result<std::reference_wrapper<const Plugin>> PluginRegistry::pluginForExtension(hilti::rt::filesystem::path ext) const {
    auto p = std::find_if(_plugins.begin(), _plugins.end(), [&](auto& p) { return p.extension == ext; });
    if ( p != _plugins.end() )
        return {*p};

    return result::Error(util::fmt("no plugin registered for extension %s", ext));
}

const Plugin& PluginRegistry::hiltiPlugin() const {
    static const Plugin* hilti_plugin = nullptr;

    if ( ! hilti_plugin ) {
        auto p = std::find_if(_plugins.begin(), _plugins.end(), [&](auto& p) { return p.component == "HILTI"; });
        if ( p == _plugins.end() )
            logger().fatalError("cannot retrieve HILTI plugin");

        hilti_plugin = &*p;
    }

    return *hilti_plugin;
}

PluginRegistry& plugin::registry() {
    static PluginRegistry singleton;
    return singleton;
}

void PluginRegistry::register_(const Plugin& p) {
    _plugins.push_back(p);
    std::sort(_plugins.begin(), _plugins.end(), [](const auto& x, const auto& y) { return x.order < y.order; });
}

// Always-on default plugin with HILTI functionality.
Plugin hilti::detail::create_hilti_plugin() {
    return Plugin{
        .component = "HILTI",
        .order = 10,
        .extension = ".hlt",
        .cxx_includes = {"hilti/rt/libhilti.h"},

        .library_paths =
            [](const std::shared_ptr<hilti::Context>& ctx) { return hilti::configuration().hilti_library_paths; },

        .parse = [](std::istream& in, const hilti::rt::filesystem::path& path) { return parseSource(in, path); },

        .coerce_ctor = [](Ctor c, const Type& dst,
                          bitmask<CoercionStyle> style) { return detail::coerceCtor(std::move(c), dst, style); },

        .coerce_type = [](Type t, const Type& dst,
                          bitmask<CoercionStyle> style) { return detail::coerceType(std::move(t), dst, style); },

        .ast_build_scopes =
            [](const std::shared_ptr<hilti::Context>& ctx, Node* m, Unit* u) {
                ast::buildScopes(ctx, m, u);
                return false;
            },

        .ast_normalize = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                            Unit* u) { return ast::normalize(m, u); },

        .ast_coerce = [](const std::shared_ptr<hilti::Context>& ctx, Node* m, Unit* u) { return ast::coerce(m, u); },

        .ast_resolve = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                          Unit* u) { return ast::resolve(ctx, m, u); },

        .ast_validate_pre =
            [](const std::shared_ptr<hilti::Context>& ctx, Node* m, Unit* u) {
                ast::validate_pre(m);
                return false;
            },

        .ast_validate_post =
            [](const std::shared_ptr<hilti::Context>& ctx, Node* m, Unit* u) {
                ast::validate_post(m);
                return false;
            },

        .ast_transform = {},
    };
}
