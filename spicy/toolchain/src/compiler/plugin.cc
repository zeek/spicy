// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <variant>

#include <hilti/ast/builder/builder.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/autogen/config.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/coercer.h>
#include <spicy/compiler/detail/parser/driver.h>
#include <spicy/compiler/detail/pir/pir.h>
#include <spicy/compiler/detail/plugin.h>
#include <spicy/compiler/detail/printer.h>
#include <spicy/compiler/detail/resolver.h>
#include <spicy/compiler/detail/scope-builder.h>
#include <spicy/compiler/detail/type-unifier.h>
#include <spicy/compiler/detail/validator.h>

using namespace spicy;
using namespace spicy::detail;

hilti::Plugin spicy::detail::createSpicyPlugin() {
    return hilti::Plugin{
        .component = "Spicy",
        .order = 5, // before HILTI
        .extension = ".spicy",
        .cxx_includes = {"spicy/rt/libspicy.h"},

        .library_paths = [](hilti::Context* /* ctx */) { return spicy::configuration().spicy_library_paths; },

        .unify_type = type_unifier::detail::unifyType,

        .parse =
            [](hilti::Builder* builder, std::istream& in, const hilti::rt::filesystem::path& path) {
                assert(dynamic_cast<spicy::Builder*>(builder));
                auto* spicy_builder = static_cast<spicy::Builder*>(builder);
                return parser::parseSource(spicy_builder, in, path.generic_string());
            },

        .coerce_ctor =
            [](hilti::Builder* builder, Ctor* c, QualifiedType* dst, bitmask<hilti::CoercionStyle> style) {
                assert(dynamic_cast<spicy::Builder*>(builder));
                auto* spicy_builder = static_cast<spicy::Builder*>(builder);
                return coercer::coerceCtor(spicy_builder, c, dst, style);
            },

        .coerce_type =
            [](hilti::Builder* builder, QualifiedType* t, QualifiedType* dst, bitmask<hilti::CoercionStyle> style) {
                assert(dynamic_cast<spicy::Builder*>(builder));
                auto* spicy_builder = static_cast<spicy::Builder*>(builder);
                return coercer::coerceType(spicy_builder, t, dst, style);
            },

        .ast_init =
            [](hilti::Builder* builder, hilti::ASTRoot* /*root*/) {
                hilti::util::timing::Collector _("spicy/compiler/ast/init");

                if ( builder->options().import_standard_modules ) {
                    builder->context()->importModule(builder, "hilti", {}, ".hlt", {}, {});
                    builder->context()->importModule(builder, "spicy_rt", {}, ".hlt", {}, {});
                    builder->context()->importModule(builder, "spicy", {}, ".spicy", {}, {});
                }
            },

        .ast_build_scopes =
            [](hilti::Builder* builder, hilti::ASTRoot* root) {
                assert(dynamic_cast<spicy::Builder*>(builder));
                auto* spicy_builder = static_cast<spicy::Builder*>(builder);
                scope_builder::build(spicy_builder, root);
                return false;
            },

        .ast_resolve =
            [](hilti::Builder* builder, Node* root) {
                assert(dynamic_cast<spicy::Builder*>(builder));
                auto* spicy_builder = static_cast<spicy::Builder*>(builder);
                return resolver::resolve(spicy_builder, root);
            },

        .ast_validate_pre =
            [](hilti::Builder* builder, hilti::ASTRoot* m) {
                assert(dynamic_cast<spicy::Builder*>(builder));
                auto* spicy_builder = static_cast<spicy::Builder*>(builder);
                validator::validatePre(spicy_builder, m);
                return false;
            },

        .ast_validate_post =
            [](hilti::Builder* builder, hilti::ASTRoot* root) {
                assert(dynamic_cast<spicy::Builder*>(builder));
                auto* spicy_builder = static_cast<spicy::Builder*>(builder);
                validator::validatePost(spicy_builder, root);
                return false;
            },

        .ast_print = [](Node* node, hilti::printer::Stream& out) { return printer::print(out, node); },

        .ast_print_id = [](const ID& id, hilti::printer::Stream& out) { return printer::printID(out, id); },

        .ast_transform = [](hilti::Builder* builder, hilti::ASTRoot* m) -> bool {
            assert(dynamic_cast<spicy::Builder*>(builder));
            auto* spicy_builder = static_cast<spicy::Builder*>(builder);

            // Read-only side path; the code generator below remains authoritative.
            if ( builder->options().getAuxOption<bool>("spicy.experimental_pir", false) ) {
                auto result = pir::build(*spicy_builder->context());
                if ( ! result ) {
                    // A failure inside PIR is not a reason to fall back.
                    hilti::logger().error(hilti::util::fmt("PIR: %s", result.error().description()));
                    return false;
                }

                if ( const auto* unsupported = std::get_if<pir::Unsupported>(&*result) ) {
                    for ( const auto& f : unsupported->features )
                        HILTI_DEBUG(spicy::logging::debug::PIR,
                                    hilti::util::fmt("unsupported: %s (%s)", f.feature, f.reason));

                    HILTI_DEBUG(spicy::logging::debug::PIR, "falling back to the standard code generator");
                }
                else
                    HILTI_DEBUG(spicy::logging::debug::PIR, "PIR built");
            }

            return CodeGen(spicy_builder).compileAST(m);
        },
    };
}
