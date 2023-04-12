// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "compiler/plugin.h"

#include <hilti/compiler/plugin.h>
#include <hilti/compiler/printer.h>

#include <spicy/ast/aliases.h>
#include <spicy/autogen/config.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/coercion.h>
#include <spicy/compiler/detail/visitors.h>
#include <spicy/global.h>

using namespace spicy;
using namespace spicy::detail;

hilti::Plugin spicy::detail::create_spicy_plugin() {
    return hilti::Plugin{
        .component = "Spicy",
        .order = 5, // before HILTI
        .extension = ".spicy",
        .cxx_includes = {"spicy/rt/libspicy.h"},

        .library_paths =
            [](const std::shared_ptr<hilti::Context>& /* ctx */) { return spicy::configuration().spicy_library_paths; },

        .parse = [](std::istream& in, const hilti::rt::filesystem::path& path) { return parseSource(in, path); },

        .coerce_ctor = [](Ctor c, const Type& dst,
                          bitmask<hilti::CoercionStyle> style) { return detail::coerceCtor(std::move(c), dst, style); },

        .coerce_type = [](Type t, const Type& dst,
                          bitmask<hilti::CoercionStyle> style) { return detail::coerceType(std::move(t), dst, style); },

        .ast_build_scopes =
            [](const std::shared_ptr<hilti::Context>& ctx, Node* m, hilti::Unit* u) {
                ast::buildScopes(ctx, m, u);
                return false;
            },

        .ast_normalize = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                            hilti::Unit* u) { return ast::normalize(ctx, m, u); },

        .ast_coerce = [](const std::shared_ptr<hilti::Context>& ctx, hilti::Node* m,
                         hilti::Unit* u) { return ast::coerce(ctx, m, u); },

        .ast_resolve = [](const std::shared_ptr<hilti::Context>& ctx, Node* m,
                          hilti::Unit* u) { return ast::resolve(ctx, m, u); },

        .ast_validate_pre =
            [](const std::shared_ptr<hilti::Context>& ctx, Node* m, hilti::Unit* u) {
                ast::validate_pre(ctx, m, u);
                return false;
            },

        .ast_validate_post =
            [](const std::shared_ptr<hilti::Context>& ctx, Node* m, hilti::Unit* u) {
                ast::validate_post(ctx, m, u);
                return false;
            },

        .ast_print = [](const Node& root, hilti::printer::Stream& out) { return ast::print(root, out); },

        .ast_transform = [](const std::shared_ptr<hilti::Context>& ctx, Node* n, hilti::Unit* u) -> bool {
            return CodeGen(ctx).compileModule(n, u);
        },
    };
}
