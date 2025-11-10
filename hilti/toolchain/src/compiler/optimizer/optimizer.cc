// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/hilti/compiler/detail/optimizer/optimizer.h"

#include <optional>
#include <string>

#include <hilti/ast/builder/builder.h>
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

cfg::CFG* ASTState::cfg(statement::Block* block) {
    assert(block);

    if ( auto it = _cfgs.find(block); it != _cfgs.end() )
        return it->second.get();
    else
        return _cfgs.emplace(block, std::make_unique<cfg::CFG>(block)).first->second.get();
}

void ASTState::functionChanged(hilti::Function* function) {
    assert(function);

    if ( _modified_functions.contains(function) )
        return;

    logging::DebugPushIndent _(logging::debug::Optimizer);
    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* new affected function: %s", function->id()));
    _modified_functions.emplace(function, nullptr); // record without module for now, will set later
}

void ASTState::moduleChanged(declaration::Module* module) {
    assert(module);

    if ( _modified_modules.contains(module) )
        return;

    logging::DebugPushIndent _(logging::debug::Optimizer);
    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* new affected module: %s", module->id()));
    _modified_modules.insert(module);
}

void ASTState::_normalizeModificationState() {
    // Remove any functions from modified set that are inside a modified
    // module; they'll be taken care of when processing the module. For all
    // others, set record their module along with the function for later use.
    // TODO: Update comments
    for ( auto& [function, module] : _modified_functions ) {
        assert(! module);

        module = function->parent<declaration::Module>(); // can be null if function has been removed in the meantime
        if ( ! module )
            HILTI_DEBUG(logging::debug::Optimizer,
                        util::fmt("  - skipping function %s as its no longer part of the AST", function->id()));
    }

    for ( auto& [block, cfg] : _cfgs ) {
        auto* module = block->parent<declaration::Module>();
        if ( ! module )
            cfg = nullptr; // block no longer part of AST
    }
}

void ASTState::updateState(const PassInfo& pinfo) {
    util::timing::Collector _1("hilti/compiler/optimizer/update-state");
    util::timing::Collector _2(util::fmt("hilti/compiler/optimizer/update-state/%s", pinfo.name));

    auto run_on_changed_nodes = [&](std::string_view requirement, const auto& callback) -> bool {
        util::timing::Collector _(util::fmt("hilti/compiler/optimizer/update-state/%s/%s", pinfo.name, requirement));

        bool modified = false;

        logging::DebugPushIndent _1(logging::debug::Optimizer);
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* %s", requirement));
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

    if ( pinfo.requires_afterwards == bitmask<Requirements>(Requirements::None) )
        return;

    HILTI_DEBUG(logging::debug::Optimizer,
                util::fmt("re-resolving AST with requirements: %s", to_string(pinfo.requires_afterwards)));

    _normalizeModificationState();

    int round = 1;

    while ( true ) {
        // The following mimics ASTContext::_resolve(), but skips steps that
        // the pass doesn't require. It also needs to run only HILTI's versions, no
        // need to consider other plugins.
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("re-resolving AST, round %d", round));
        auto modified = false;

        if ( pinfo.requires_afterwards & Requirements::ScopeBuilder ) {
            run_on_changed_nodes("scope-builder", [&](auto* node) {
                context()->clearScopes(builder(), node);
                scope_builder::build(builder(), node);
                return false; // no need to track modifications here
            });
        }

        if ( pinfo.requires_afterwards & Requirements::TypeUnifier )
            run_on_changed_nodes("type-unifier", [&](auto* node) { return type_unifier::unify(builder(), node); });

        if ( (pinfo.requires_afterwards & Requirements::FullResolver) )
            run_on_changed_nodes("full-resolver", [&](auto* node) { return resolver::resolve(builder(), node); });

        else if ( pinfo.requires_afterwards & Requirements::Coercer )
            // This is implicitly also part of the full resolver, so only need
            // to run if that one doesn't.
            run_on_changed_nodes("coercer", [&](auto* node) { return resolver::coerce(builder(), node); });

        if ( pinfo.requires_afterwards & Requirements::ConstantFolder )
            run_on_changed_nodes("constant-folder", [&](auto* node) {
                return constant_folder::fold(builder(), node,
                                             constant_folder::Style::InlineFeatureConstants |
                                                 constant_folder::Style::InlineBooleanConstants |
                                                 constant_folder::Style::FoldTernaryOperator);
            });

        if ( pinfo.requires_afterwards & Requirements::CFG ) {
            logging::DebugPushIndent _1(logging::debug::Optimizer);
            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("* computed CFGs"));
            logging::DebugPushIndent _2(logging::debug::Optimizer);

            for ( const auto& [function, module] : _modified_functions ) {
                if ( ! module )
                    continue; // no longer in AST

                if ( _modified_modules.contains(module) ) // will be handled when processing module
                    continue;

                if ( auto* block = function->body() )
                    if ( _cfgs.erase(block->as<statement::Block>()) )
                        HILTI_DEBUG(logging::debug::Optimizer,
                                    util::fmt("- deleting function state: %s", function->id()));
            }

            for ( auto* module : _modified_modules ) {
                if ( auto* block = module->statements() )
                    if ( _cfgs.erase(block) )
                        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("- deleting module state: %s", module->id()));

                for ( const auto& [function, fmodule] : _modified_functions ) {
                    if ( fmodule != module )
                        continue;

                    if ( auto* body = function->body(); body && _cfgs.erase(body->as<statement::Block>()) )
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

void ASTState::checkState(const PassInfo& pinfo) {
    // In debug builds, we check the AST after each pass to enforce that it's
    // been left in good shape. In release builds, this is a no-op for performance.
#ifndef NDEBUG
    util::timing::Collector _("hilti/compiler/optimizer/check-state");

    context()->checkAST();

    validator::detail::validatePost(builder(), context()->root());
    if ( ! context()->collectErrors() )
        logger().internalError("Optimizer::_checkState: AST is not valid after optimizer pass");

    if ( ! type_unifier::check(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST types are not fully unified after optimizer pass %s", pinfo.name));

    if ( scope_builder::buildToValidate(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST scopes are not fully built after optimizer pass %s", pinfo.name));

    // We check folding here without the additional styles otherwise used
    // inside the optimizer, because that's what the normal resolver does. If
    // we checked for them here, we could trigger in case the original AST,
    // which only went through that standard resolving, gets here.
    if ( constant_folder::fold(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST is not fully constant folded after optimizer pass %s", pinfo.name));

    if ( resolver::coerce(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST is not fully coerced after optimizer pass %s", pinfo.name));

    if ( resolver::resolve(builder(), context()->root()) )
        logger().internalError(
            util::fmt("Optimizer::_checkState: AST is not fully resolved after optimizer pass %s", pinfo.name));

    for ( const auto& [block, cfg] : _cfgs ) {
        assert(block);

        if ( ! cfg )
            continue; // block no longer part of AST

        auto actual = cfg->dot(false);
        auto expected = cfg::CFG(block).dot(false);
        if ( actual != expected ) {
            std::cerr << "==== ACTUAL   ===\n\n" << actual << "\n\n";
            std::cerr << "==== EXPECTED ===\n\n" << expected << "\n\n";

            auto* decl = block->parent<Declaration>();
            assert(decl);

            logger().internalError(
                util::fmt("Optimizer::_checkState: CFG for %s \"%s\" is not up to date after optimizer pass %s",
                          decl->typename_(), decl->id(), pinfo.name));
        }
    }
#endif
}


std::string optimizer::to_string(bitmask<Requirements> r) {
    std::vector<std::string> labels;

    if ( r & Requirements::CFG )
        labels.emplace_back("cfg");

    if ( r & Requirements::Coercer )
        labels.emplace_back("coercer");

    if ( r & Requirements::ConstantFolder )
        labels.emplace_back("constant-folder");

    if ( r & Requirements::FullResolver )
        labels.emplace_back("full-resolver");

    if ( r & Requirements::ScopeBuilder )
        labels.emplace_back("scope-builder");

    if ( r & Requirements::TypeUnifier )
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

        auto _guard = util::scope_exit([&]() { _state.setPass(nullptr); });
        _state.setPass(&pinfo);

        bool modified_by_pass = false;
        {
            util::timing::Collector __(util::fmt("hilti/compiler/optimizer/pass/%s", pinfo.name));
            modified_by_pass = ((*pinfo.run)(this) == optimizer::Result::Modified);
            modified |= modified_by_pass;
        }

        if ( modified_by_pass ) {
            HILTI_DEBUG(logging::debug::Optimizer, "  -> modified");

            if ( logger().isEnabled(logging::debug::OptimizerDump) ) {
                const auto fname = util::fmt("%zu-%03zu-%zu-%s", round, pinfo.order, iteration, pinfo.name);
                const auto header = util::
                    fmt("State after modifications by pass %s, round %zu, pass iteration %zu, before fixing "
                        "requirements",
                        pinfo.name, round, iteration);
                _dumpAST(context(), fname, header);
            }

            _state.updateState(pinfo);

            if ( logger().isEnabled(logging::debug::OptimizerDump) ) {
                const auto fname = util::fmt("%zu-%03zu-%zu-%s-fixed", round, pinfo.order, iteration, pinfo.name);
                const auto header = util::
                    fmt("State after modifications by pass %s, round %zu, pass iteration %zu, after fixing "
                        "requirements",
                        pinfo.name, round, iteration);
                _dumpAST(context(), fname, header);
            }

            _state.checkState(pinfo);
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

    // TODO: We could probably just assert there are no error set in the AST.
    context()->clearErrors(builder());

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
                // TODO: This is just in the interest not changing any output
                // compared to before the refactoring of the optimizer.
                // Specifically, hilti.output.optimization.const breaks without
                // this. We should revisit whether we need to to keep this
                // behavior once we have confidence the new optimizer is
                // generally producing correct code.
                modified_by_pass |= constant_folder::fold(builder(), context()->root(),
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

    if ( ! context()->compilerContext()->options().skip_validation ) {
        validator::detail::validatePost(builder(), context()->root());

        if ( auto rc = context()->collectErrors(); ! rc )
            return rc;
    }

    return Nothing();
}


// Helper function to extract innermost type, removing any wrapping in reference or container types.
QualifiedType* Optimizer::innermostType(QualifiedType* type) {
    if ( type->type()->isReferenceType() )
        return innermostType(type->type()->dereferencedType());

    if ( type->type()->iteratorType() )
        return innermostType(type->type()->elementType());

    return type;
}

// Helper to extract `(ID, feature)` from a feature constant.
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
