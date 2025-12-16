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

ASTState::ASTState(ASTContext* ctx, Builder* builder, cfg::Cache* cfg_cache)
    : _context(ctx), _builder(builder), _cfg_cache(cfg_cache) {
#ifndef NDEBUG
    // Ensure the CFG cache is valid to begin with.
    _cfg_cache->checkValidity();
#endif
}

void ASTState::functionChanged(hilti::Function* function) {
    assert(function);

    if ( _modified_functions.contains(function) )
        return;

    logging::DebugPushIndent _(logging::debug::Optimizer);
    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* function changed: %s", function->id()));
    _modified_functions.insert(function); // record without module for now, will set later
}

void ASTState::moduleChanged(declaration::Module* module) {
    assert(module);

    if ( _modified_modules.contains(module) )
        return;

    logging::DebugPushIndent _(logging::debug::Optimizer);
    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* module changed: %s", module->id()));
    _modified_modules.insert(module);
}

bool ASTState::_resolve(Node* node) {
    // This mimics ASTContext::_resolve(), reduced to just the steps the
    // optimizer needs. In particular that means not running any plugins
    // because we have a pure HILTI AST at this point. It
    // also runs only on changed parts of the AST.
    bool ever_changed = false;
    unsigned int round = 1;

    while ( true ) {
        auto changed = scope_builder::build(_builder, node);
        changed |= type_unifier::unify(_builder, node);
        changed |= resolver::resolve(_builder, node);
        ever_changed |= changed;

        if ( ! changed )
            return ever_changed;

        if ( ++round >= ASTContext::MaxASTIterationRounds )
            logger().internalError(
                "Optimizer: ASTState::updateAST() didn't terminate during resolving, AST keeps changing");
    }
}

void ASTState::updateAST(const PassInfo& pinfo) {
    util::timing::Collector _1("hilti/compiler/optimizer/update-state");
    util::timing::Collector _2(util::fmt("hilti/compiler/optimizer/update-state/%s", to_string(pinfo.id)));

    auto run_on_changed_nodes = [&](std::string_view post_processor, const auto& callback) -> bool {
        util::timing::Collector _(
            util::fmt("hilti/compiler/optimizer/update-state/%s/%s", to_string(pinfo.id), post_processor));

        bool modified = false;

        logging::DebugPushIndent _1(logging::debug::Optimizer);
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* %s", post_processor));
        logging::DebugPushIndent _2(logging::debug::Optimizer);

        for ( const auto& function : _modified_functions ) {
            auto* module = function->parent<declaration::Module>();
            if ( ! module )
                continue; // no longer in AST

            if ( _modified_modules.contains(module) )
                continue; // will be handled when processing module

            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("- updating function: %s", function->id()));
            modified |= callback(function->parent());
        }

        for ( const auto& m : _modified_modules ) {
            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("- updating module: %s", m->id()));
            modified |= callback(m);
        }

        return modified;
    };

    if ( pinfo.guarantees == bitmask<Guarantees>(Guarantees::All) )
        return;

    HILTI_DEBUG(logging::debug::Optimizer,
                util::fmt("re-resolving AST assuming guarantees %s", to_string(pinfo.guarantees)));

    _cfg_cache->prune();

    unsigned int round = 1;

    while ( true ) {
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("re-processing AST, round %d", round));

        auto modified = false;

        if ( ! (pinfo.guarantees & Guarantees::Resolved) )
            run_on_changed_nodes("resolver", [&](auto* node) { return _resolve(node); });

        if ( ! (pinfo.guarantees & Guarantees::ConstantsFolded) )
            run_on_changed_nodes("constant-folder", [&](auto* node) {
                return constant_folder::fold(_builder, node,
                                             constant_folder::Style::InlineFeatureConstants |
                                                 constant_folder::Style::InlineBooleanConstants |
                                                 constant_folder::Style::FoldTernaryOperator);
            });

        if ( ! (pinfo.guarantees & Guarantees::CFGUnchanged) ) {
            logging::DebugPushIndent _1(logging::debug::Optimizer);
            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* computed CFGs"));
            logging::DebugPushIndent _2(logging::debug::Optimizer);

            for ( const auto& function : _modified_functions ) {
                if ( auto* block = function->body() ) {
                    if ( cfgCache()->invalidate(block) )
                        HILTI_DEBUG(logging::debug::Optimizer,
                                    util::fmt("- deleting function state: %s", function->id()));
                }
            }

            for ( auto* module : _modified_modules ) {
                if ( cfgCache()->invalidate(module) )
                    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("- deleting module state: %s", module->id()));
            }
        }

        if ( ! modified )
            break;

        HILTI_DEBUG(logging::debug::Optimizer, "  -> modified");

        if ( ++round >= ASTContext::MaxASTIterationRounds )
            logger().internalError("Optimizer::_updateState() didn't terminate, AST keeps changing");
    }

    _modified_functions.clear();
    _modified_modules.clear();
}

#ifndef NDEBUG
void ASTState::checkAST(PassID pass_id) {
    // In debug builds, we check the AST after each pass to enforce that it's
    // been left in good shape.
    util::timing::Collector _("hilti/compiler/optimizer/check-state");

    context()->checkAST();

    validator::detail::validatePost(_builder, context()->root());
    if ( ! context()->collectErrors() )
        logger().internalError("Optimizer::_checkState: AST is not valid after optimizer pass");

    if ( ! type_unifier::check(_builder, context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST types are not fully unified after optimizer pass %s",
                      to_string(pass_id)));

    if ( scope_builder::build(_builder, context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST scopes are not fully built after optimizer pass %s",
                      to_string(pass_id)));

    // We check folding here without the any additional styles otherwise used
    // inside the optimizer, because that's what the normal resolver does. If
    // we checked for them here, we could trigger in case the original AST,
    // which only went through that standard resolving, gets here unmodified.
    if ( constant_folder::fold(_builder, context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST is not fully constant folded after optimizer pass %s",
                      to_string(pass_id)));

    if ( resolver::resolve(_builder, context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST is not fully resolved after optimizer pass %s", to_string(pass_id)));

    _cfg_cache->checkValidity();
}
#endif

std::string optimizer::to_string(bitmask<Guarantees> r) {
    std::vector<std::string> labels;

    if ( r & Guarantees::CFGUnchanged )
        labels.emplace_back("cfg-unchanged");

    if ( r & Guarantees::ConstantsFolded )
        labels.emplace_back("constants-folded");

    if ( r & Guarantees::Resolved )
        labels.emplace_back("resolved");

    if ( labels.empty() )
        return "<none>";
    else
        return util::fmt("<%s>", util::join(labels, ","));
}

Optimizer::Optimizer(Builder* builder) : _builder(builder), _state(builder->context(), builder, &_cfgs) {}

bool Optimizer::_runPass(const optimizer::PassInfo& pinfo, unsigned int round) {
    unsigned int iteration = 1;
    bool modified = false;

    while ( true ) {
        HILTI_DEBUG(logging::debug::Optimizer,
                    util::fmt("pass: %s (round %zu, pass iteration %zu)", to_string(pinfo.id), round, iteration));
        logging::DebugPushIndent _(logging::debug::Optimizer);

        bool modified_by_pass = false;

        {
            util::timing::Collector _1(util::fmt("hilti/compiler/optimizer/pass/%s", to_string(pinfo.id)));
            auto _2 = _state.trackPass(&pinfo);
            modified_by_pass = (*pinfo.run)(this);
            modified |= modified_by_pass;
        }

        if ( modified_by_pass ) {
            HILTI_DEBUG(logging::debug::Optimizer, "  -> modified");

            if ( logger().isEnabled(logging::debug::OptimizerDump) ) {
                const auto fname =
                    util::fmt("%zu-%03zu-%zu-%s", round, static_cast<int>(pinfo.id), iteration, to_string(pinfo.id));
                const auto header = util::
                    fmt("State after modifications by pass %s, round %zu, pass iteration %zu, before running "
                        "post-processors",
                        to_string(pinfo.id), round, iteration);
                _dumpAST(context(), fname, header);
            }

            _state.updateAST(pinfo);

            if ( logger().isEnabled(logging::debug::OptimizerDump) ) {
                const auto fname =
                    util::fmt("%zu-%03zu-%zu-%s-pp", round, static_cast<int>(pinfo.id), iteration, to_string(pinfo.id));
                const auto header = util::
                    fmt("State after modifications by pass %s, round %zu, pass iteration %zu, after running "
                        "post-processors",
                        to_string(pinfo.id), round, iteration);
                _dumpAST(context(), fname, header);
            }

#ifndef NDEBUG
#ifndef HILTI_SKIP_EXPENSIVE_DEBUG_CHECKS
            // This AST check is expensive to perform after each pass. It's
            // enabled by default in debug builds, but can be disabled at build
            // time by defining HILTI_SKIP_EXPENSIVE_DEBUG_CHECKS. There is a
            // corresponding CMake option as well.
            _state.checkAST(pinfo.id);
#endif
#endif
        }

        if ( ! modified_by_pass || ! pinfo.iterate )
            break;

        if ( ++iteration >= ASTContext::MaxASTIterationRounds )
            logger().internalError(util::fmt("Optimizer::_runPass() didn't terminate, AST keeps changing in pass %s",
                                             to_string(pinfo.id)));
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

    unsigned int round = 1;

    while ( true ) {
        bool modified = false;

        for ( const auto& pinfo : optimizer::getPassRegistry()->passes() ) {
            if ( pinfo.one_time && round > 1 )
                continue;

            auto modified_by_pass = _runPass(pinfo, round);
            modified |= modified_by_pass;

            if ( round == 1 && ! modified_by_pass && pinfo.id == PassID::FeatureRequirements ) {
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

        if ( ++round >= ASTContext::MaxASTIterationRounds )
            logger().internalError("Optimizer::run() didn't terminate, optimizer keeps changing AST");
    }

    if ( logger().isEnabled(logging::debug::OptimizerDump) )
        _dumpAST(context(), util::fmt("%d-000-x-final", round), "Final state after optimization");

    return Nothing();
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
