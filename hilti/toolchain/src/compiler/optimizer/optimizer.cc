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

std::string optimizer::to_string(bitmask<Requirements> r) {
    std::vector<std::string> labels;

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

Optimizer::Optimizer(ASTContext* ctx) : _context(ctx), _builder(ctx) {}

void Optimizer::_updateState(const PassInfo& pinfo) {
    util::timing::Collector _("hilti/compiler/optimizer/update-state");

    // This mimics ASTContext::_resolve(), but skips steps that the pass
    // doesn't require. It also needs to run only HILTI's versions, no need to
    // consider other plugins.

    if ( pinfo.requires_afterwards == bitmask<Requirements>(Requirements::None) )
        return;

    int round = 1;

    while ( true ) {
        // Loop body mimics ASTContext::_resolve() for a single plugin.
        HILTI_DEBUG(logging::debug::Optimizer,
                    util::fmt("re-resolving AST with requirements: %s", to_string(pinfo.requires_afterwards)));
        auto modified = false;

        if ( pinfo.requires_afterwards & Requirements::ScopeBuilder ) {
            context()->clearScopes(builder());
            scope_builder::build(builder(), context()->root()); // don't need/have modified tracking here
        }

        if ( pinfo.requires_afterwards & Requirements::TypeUnifier )
            modified = type_unifier::unify(builder(), context()->root());

        if ( pinfo.requires_afterwards & Requirements::FullResolver )
            modified = resolver::resolve(builder(), context()->root());

        else {
            // These are implicitly also part of the full resolver, so only
            // need to run if that one doesn't.
            if ( pinfo.requires_afterwards & Requirements::Coercer )
                modified = resolver::coerce(builder(), context()->root());

            if ( pinfo.requires_afterwards & Requirements::ConstantFolder )
                modified = constant_folder::fold(builder(), context()->root(),
                                                 constant_folder::Style::InlineFeatureConstants |
                                                     constant_folder::Style::InlineBooleanConstants |
                                                     constant_folder::Style::FoldTernaryOperator);
        }

        if ( ! modified )
            break;

        HILTI_DEBUG(logging::debug::Optimizer, "    -> modified");

        if ( ++round >= 50 )
            logger().internalError("Optimizer::_updateState() didn't terminate, AST keeps changing");
    }
}

void Optimizer::_checkState(const PassInfo& pinfo) {
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

    // TODO: Later also check cfg.
#endif
}

bool Optimizer::_runPass(const optimizer::PassInfo& pinfo, size_t round) {
    util::timing::Collector __(util::fmt("hilti/compiler/optimizer/%s", pinfo.name));

    size_t iteration = 1;
    bool modified = false;

    while ( true ) {
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("pass: %s with order %d (round %zu, pass iteration %zu)",
                                                         pinfo.name, pinfo.order, round, iteration));
        logging::DebugPushIndent _(logging::debug::Optimizer);

        ASTState state(context());
        state.pass = &pinfo;
        _state = &state;

        auto modified_by_pass = ((*pinfo.run)(this) == optimizer::Result::Modified);
        modified |= modified_by_pass;

        if ( modified_by_pass ) {
            HILTI_DEBUG(logging::debug::Optimizer, "    -> modified");

            _updateState(pinfo);
            _checkState(pinfo);

            if ( logger().isEnabled(logging::debug::OptimizerDump) ) {
                const auto fname = util::fmt("%zu-%03zu-%zu-%s", round, pinfo.order, iteration, pinfo.name);
                const auto header = util::fmt("State after modifications by pass %s, round %zu, pass iteration %zu",
                                              pinfo.name, round, iteration);
                _dumpAST(context(), fname, header);
            }
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
