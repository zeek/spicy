// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/hilti/compiler/detail/optimizer/optimizer.h"

#include <optional>
#include <string>

#include <hilti/ast/builder/builder.h>
#include <hilti/autogen/config.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/constant-folder.h>
#include <hilti/compiler/detail/resolver.h>
#include <hilti/compiler/detail/scope-builder.h>
#include <hilti/compiler/type-unifier.h>
#include <hilti/compiler/validator.h>
#include <hilti/hilti/hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

CFG* ASTState::cfg(statement::Block* block) {
    assert(block);

    if ( auto it = _cfgs.find(block); it != _cfgs.end() )
        return it->second.get();
    else
        return _cfgs.emplace(block, std::make_unique<CFG>(block)).first->second.get();
}

void ASTState::functionChanged(hilti::Function* function) {
    assert(function);

    if ( _modified_functions.contains(function) )
        return;

    logging::DebugPushIndent _(logging::debug::Optimizer);
    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* function changed: %s", function->id()));
    _modified_functions.emplace(function, nullptr); // record without module for now, will set later
}

void ASTState::moduleChanged(declaration::Module* module) {
    assert(module);

    if ( _modified_modules.contains(module) )
        return;

    logging::DebugPushIndent _(logging::debug::Optimizer);
    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* module changed: %s", module->id()));
    _modified_modules.insert(module);
}

void ASTState::_normalizeModificationState() {
    // Go through modified functions and now set their parent module (which was
    // left unset during insertion into the set).
    for ( auto& [function, module] : _modified_functions ) {
        assert(! module); // was left unset

        module = function->parent<declaration::Module>();
        if ( ! module )
            // This can happen if the function has been removed from the AST in
            // the meantime. We still leave the function in the set, but let
            // its module remain unset.
            HILTI_DEBUG(logging::debug::Optimizer,
                        util::fmt("  - skipping function %s as its no longer part of the AST", function->id()));
    }

    // Go through cached CFGs and invalidate any whose block is no longer part
    // of the AST.
    for ( auto& [block, cfg] : _cfgs ) {
        if ( ! block->parent<declaration::Module>() )
            cfg = nullptr;
    }
}

void ASTState::updateAST(const PassInfo& pinfo) {
    util::timing::Collector _1("hilti/compiler/optimizer/update-state");
    util::timing::Collector _2(util::fmt("hilti/compiler/optimizer/update-state/%s", pinfo.name));

    auto run_on_changed_nodes = [&](std::string_view post_processor, const auto& callback) -> bool {
        util::timing::Collector _(util::fmt("hilti/compiler/optimizer/update-state/%s/%s", pinfo.name, post_processor));

        bool modified = false;

        logging::DebugPushIndent _1(logging::debug::Optimizer);
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* %s", post_processor));
        logging::DebugPushIndent _2(logging::debug::Optimizer);

        for ( const auto& [function, module] : _modified_functions ) {
            if ( ! module )
                continue; // no longer in AST

            if ( _modified_modules.contains(module) ) // will be handled when processing module
                continue;

            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("- updating function: %s", function->id()));
            modified |= callback(function->parent());
        }

        for ( const auto& m : _modified_modules ) {
            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("- updating module: %s", m->id()));
            modified |= callback(m);
        }

        return modified;
    };

    if ( pinfo.post_processors == bitmask<PostProcessors>(PostProcessors::None) )
        return;

    HILTI_DEBUG(logging::debug::Optimizer,
                util::fmt("re-resolving AST with post-processor: %s", to_string(pinfo.post_processors)));

    _normalizeModificationState();

    int round = 1;

    while ( true ) {
        // The following mimics ASTContext::_resolve(), but skips steps that
        // the pass doesn't require. It also runs only on changed parts of the
        // AST; it needs to run only HILTI's versions, no
        // need to consider other compiler plugins.
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("re-resolving AST, round %d", round));

        auto modified = false;

        if ( pinfo.post_processors & PostProcessors::ScopeBuilder ) {
            run_on_changed_nodes("scope-builder", [&](auto* node) {
                context()->clearScopes(node);
                scope_builder::build(builder(), node);
                return false; // no need to track modifications here
            });
        }

        if ( pinfo.post_processors & PostProcessors::TypeUnifier )
            run_on_changed_nodes("type-unifier", [&](auto* node) { return type_unifier::unify(builder(), node); });

        if ( (pinfo.post_processors & PostProcessors::FullResolver) )
            run_on_changed_nodes("full-resolver", [&](auto* node) { return resolver::resolve(builder(), node); });

        else if ( pinfo.post_processors & PostProcessors::Coercer )
            // This is implicitly also part of the full resolver, so only need
            // to run if that one doesn't.
            run_on_changed_nodes("coercer", [&](auto* node) { return resolver::coerce(builder(), node); });

        if ( pinfo.post_processors & PostProcessors::ConstantFolder )
            run_on_changed_nodes("constant-folder", [&](auto* node) {
                return constant_folder::fold(builder(), node,
                                             constant_folder::Style::InlineFeatureConstants |
                                                 constant_folder::Style::InlineBooleanConstants |
                                                 constant_folder::Style::FoldTernaryOperator);
            });

        if ( pinfo.post_processors & PostProcessors::CFG ) {
            logging::DebugPushIndent _1(logging::debug::Optimizer);
            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* computed CFGs"));
            logging::DebugPushIndent _2(logging::debug::Optimizer);

            for ( const auto& [function, module] : _modified_functions ) {
                if ( ! module )
                    continue; // no longer in AST

                if ( _modified_modules.contains(module) ) // will be handled when processing module
                    continue;

                if ( auto* block = function->body() ) {
                    if ( _cfgs.erase(block->as<statement::Block>()) )
                        HILTI_DEBUG(logging::debug::Optimizer,
                                    util::fmt("- deleting function state: %s", function->id()));
                }
            }

            for ( auto* module : _modified_modules ) {
                if ( auto* block = module->statements() ) {
                    if ( _cfgs.erase(block) )
                        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("- deleting module state: %s", module->id()));
                }

                for ( const auto& [function, fmodule] : _modified_functions ) {
                    if ( fmodule != module )
                        continue;

                    if ( auto* body = function->body(); body && _cfgs.erase(body) )
                        HILTI_DEBUG(logging::debug::Optimizer,
                                    util::fmt("  * deleting function state: %s (via module %s)", function->id(),
                                              module->id()));
                }
            }
        }

        if ( ! modified )
            break;

        HILTI_DEBUG(logging::debug::Optimizer, "  -> modified");

        if ( ++round >= 50 )
            logger().internalError("Optimizer::_updateState() didn't terminate, AST keeps changing");
    }

    _modified_functions.clear();
    _modified_modules.clear();
}

#ifndef NDEBUG
void ASTState::checkAST(std::string_view pass_name) {
    // In debug builds, we check the AST after each pass to enforce that it's
    // been left in good shape.
    util::timing::Collector _("hilti/compiler/optimizer/check-state");

    context()->checkAST();

    validator::detail::validatePost(builder(), context()->root());
    if ( ! context()->collectErrors() )
        logger().internalError("Optimizer::_checkState: AST is not valid after optimizer pass");

    if ( ! type_unifier::check(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST types are not fully unified after optimizer pass %s", pass_name));

    if ( scope_builder::build(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST scopes are not fully built after optimizer pass %s", pass_name));

    // We check folding here without the any additional styles otherwise used
    // inside the optimizer, because that's what the normal resolver does. If
    // we checked for them here, we could trigger in case the original AST,
    // which only went through that standard resolving, gets here unmodified.
    if ( constant_folder::fold(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST is not fully constant folded after optimizer pass %s", pass_name));

    if ( resolver::coerce(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST is not fully coerced after optimizer pass %s", pass_name));

    if ( resolver::resolve(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST is not fully resolved after optimizer pass %s", pass_name));

    // Go through cached CFGs and verify that they are still up to date.
    for ( const auto& [block, cfg] : _cfgs ) {
        assert(block);

        if ( ! cfg )
            continue; // block no longer part of AST

        auto actual = cfg->dot(false);
        auto expected = CFG(block).dot(false);

        if ( actual != expected ) {
            std::cerr << "==== ACTUAL   ===\n\n" << actual << "\n\n";
            std::cerr << "==== EXPECTED ===\n\n" << expected << "\n\n";

            auto* decl = block->parent<Declaration>();
            assert(decl);

            logger().internalError(
                util::fmt("Optimizer::_checkState: CFG for %s \"%s\" is not up to date after optimizer pass %s",
                          decl->typename_(), decl->id(), pass_name));
        }
    }
}
#endif

std::string optimizer::to_string(bitmask<PostProcessors> r) {
    std::vector<std::string> labels;

    if ( r & PostProcessors::CFG )
        labels.emplace_back("cfg");

    if ( r & PostProcessors::Coercer )
        labels.emplace_back("coercer");

    if ( r & PostProcessors::ConstantFolder )
        labels.emplace_back("constant-folder");

    if ( r & PostProcessors::FullResolver )
        labels.emplace_back("full-resolver");

    if ( r & PostProcessors::ScopeBuilder )
        labels.emplace_back("scope-builder");

    if ( r & PostProcessors::TypeUnifier )
        labels.emplace_back("type-unifier");

    if ( labels.empty() )
        return "<none>";
    else
        return util::fmt("<%s>", util::join(labels, ","));
}

Optimizer::Optimizer(ASTContext* ctx) : _context(ctx), _builder(ctx), _state(ctx, &_builder) {}

bool Optimizer::_runPass(const optimizer::PassInfo& pinfo, size_t round) {
    size_t iteration = 1;
    bool modified = false;

    while ( true ) {
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("pass: %s with order %d (round %zu, pass iteration %zu)",
                                                         pinfo.name, pinfo.order, round, iteration));
        logging::DebugPushIndent _(logging::debug::Optimizer);

        bool modified_by_pass = false;

        {
            util::timing::Collector _1(util::fmt("hilti/compiler/optimizer/pass/%s", pinfo.name));
            auto _2 = _state.trackPass(&pinfo);
            modified_by_pass = (*pinfo.run)(this);
            modified |= modified_by_pass;
        }

        if ( modified_by_pass ) {
            HILTI_DEBUG(logging::debug::Optimizer, "  -> modified");

            if ( logger().isEnabled(logging::debug::OptimizerDump) ) {
                const auto fname = util::fmt("%zu-%03zu-%zu-%s", round, pinfo.order, iteration, pinfo.name);
                const auto header = util::
                    fmt("State after modifications by pass %s, round %zu, pass iteration %zu, before running "
                        "post-processors",
                        pinfo.name, round, iteration);
                _dumpAST(context(), fname, header);
            }

            _state.updateAST(pinfo);

            if ( logger().isEnabled(logging::debug::OptimizerDump) ) {
                const auto fname = util::fmt("%zu-%03zu-%zu-%s-pp", round, pinfo.order, iteration, pinfo.name);
                const auto header = util::
                    fmt("State after modifications by pass %s, round %zu, pass iteration %zu, after running "
                        "post-processors",
                        pinfo.name, round, iteration);
                _dumpAST(context(), fname, header);
            }

#ifndef NDEBUG
#ifndef HILTI_SKIP_EXPENSIVE_DEBUG_CHECKS
            // This AST check is expensive to perform after each pass. It's
            // enabled by default in debug builds, but can be disabled at build
            // time by defining HILTI_SKIP_EXPENSIVE_DEBUG_CHECKS. There is a
            // corresponding CMake option as well.
            _state.checkAST(pinfo.name);
#endif
#endif
        }

        if ( ! modified_by_pass || ! pinfo.iterate )
            break;

        if ( ++iteration >= 50 )
            logger().internalError(
                util::fmt("Optimizer::_runPass() didn't terminate, AST keeps changing in pass %s", pinfo.name));
    };

    return modified;
}

void Optimizer::_dumpAST(ASTContext* ctx, std::string_view fname, std::string_view header) {
    std::ofstream out_ast(util::fmt("optimizer-ast-%s.tmp", fname));
    out_ast << " # " << header << "\n\n";
    ctx->dump(out_ast, true);

    std::ofstream out_hlt(util::fmt("optimizer-hlt-%s.tmp", fname));
    out_hlt << "# " << header << "\n\n";
    ctx->root()->print(out_hlt, false, true);
}

hilti::Result<Nothing> Optimizer::run() {
    util::timing::Collector _("hilti/compiler/optimizer");

    if ( logger().isEnabled(logging::debug::OptimizerDump) )
        _dumpAST(context(), "0-000-0-initial", "Initial state before optimization");

    size_t round = 1;

    while ( true ) {
        bool modified = false;

        for ( const auto& pinfo : optimizer::getPassRegistry()->passes() ) {
            if ( pinfo.one_time && round > 1 )
                continue;

            auto modified_by_pass = _runPass(pinfo, round);
            modified |= modified_by_pass;

            if ( round == 1 && ! modified_by_pass && pinfo.name == "feature-requirements" ) {
                // TODO: This is a special-case just in the interest of not
                // changing any output compared to before the refactoring of
                // the optimizer. Specifically, hilti.output.optimization.const
                // breaks without this. Once we are fine changing output, we
                // can revisit whether we need to to keep this behavior.
                modified |= constant_folder::fold(builder(), context()->root(),
                                                  constant_folder::Style::InlineBooleanConstants |
                                                      constant_folder::Style::FoldTernaryOperator);
            }
        };

        if ( ! modified )
            break;

        if ( ++round >= 50 )
            logger().internalError("Optimizer::run() didn't terminate, optimizer keeps changing AST");
    }

    if ( logger().isEnabled(logging::debug::OptimizerDump) )
        _dumpAST(context(), util::fmt("%d-000-x-final", round), "Final state after optimization");

    return Nothing();
}


QualifiedType* Optimizer::innermostType(QualifiedType* type) {
    if ( type->type()->isReferenceType() )
        return innermostType(type->type()->dereferencedType());

    if ( type->type()->iteratorType() )
        return innermostType(type->type()->elementType());

    return type;
}

std::optional<std::pair<ID, std::string>> Optimizer::idFeatureFromConstant(const ID& feature_constant) {
    const auto& id = feature_constant.local();

    if ( ! isFeatureFlag(id) )
        return {};

    const auto& tokens = util::split(id, "%");
    assert(tokens.size() == 3);

    auto type_id = ID(util::replace(tokens[1], "@@", "::"));
    const auto& feature = tokens[2];

    return {{type_id, feature}};
};
