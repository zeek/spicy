// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/collector-callers.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

/**
 * Collects function parameters that can be optimized based on their usage inside
 * the body.
 */
struct CollectorParameters : public optimizer::visitor::Collector {
    CollectorParameters(Optimizer* optimizer, const CollectorCallers* operators)
        : optimizer::visitor::Collector(optimizer), collector_callers(operators) {}

    const CollectorCallers* collector_callers;

    // The unused parameters for a given function ID
    std::map<ID, std::vector<std::size_t>> unused_params;

    // Parameters of kind `copy/`inout` that are promotable to `in`.
    std::set<declaration::Parameter*> promotable_params;

    /**
     * Determines if the uses of this operator contain any side effects.
     * Currently, this means a function call that contains another function
     * call as an argument.
     *
     * TODO: Eventually we should be able to just call
     * cfgCache()->mayHaveSideEffects() on the operator itself, but that
     * currently doesn't provide the resolution we need.
     */
    bool usesContainSideEffects(const Operator* op) {
        const auto* uses_of_op = collector_callers->uses(op);
        if ( ! uses_of_op )
            return false;

        for ( const auto* use : *uses_of_op ) {
            if ( ! use->isA<operator_::function::Call>() && ! use->isA<operator_::struct_::MemberCall>() )
                continue;

            bool is_method = use->isA<operator_::struct_::MemberCall>();

            // Get the params as a tuple
            const auto* ctor =
                is_method ? use->op2()->tryAs<expression::Ctor>() : use->op1()->tryAs<expression::Ctor>();
            if ( ! ctor )
                continue;

            const auto* tup = ctor->ctor()->tryAs<ctor::Tuple>();
            if ( ! tup )
                continue;

            for ( const auto* arg : tup->value() ) {
                if ( arg->isA<operator_::function::Call>() )
                    return true;
            }
        }

        return false;
    }

    /** Removes the param_id as used within the function. */
    void removeUsed(const type::Function* ftype, const ID& function_id, const Expression* name) {
        auto& unused = unused_params.at(function_id);

        std::string_view id = {};
        const Declaration* resolved_declaration = nullptr;

        if ( const auto* x = name->tryAs<expression::Name>() ) {
            id = x->id().str();
            assert(x->resolvedDeclaration());
            resolved_declaration = x->resolvedDeclaration();
        }
        else
            util::detail::internalError(util::fmt("unexpected expression '%s'", name));

        const auto& params = ftype->parameters();
        for ( auto it = unused.begin(); it != unused.end(); ++it ) {
            auto param_num = *it;
            assert(params.size() >= param_num);

            if ( params[param_num]->id() != id )
                continue;

            if ( resolved_declaration && resolved_declaration != params[param_num] )
                continue;

            unused.erase(it, std::next(it));
            break;
        }
    }

    /**
     * Helper returning the set of parameters that are possibly modified
     * anywhere inside the given function body, according to our CFG's dataflow
     * information.
     */
    std::set<const declaration::Parameter*> modifiedParameters(statement::Block* body, optimizer::ASTState* state) {
        auto* cfg = state->cfgCache()->get(body);
        if ( ! cfg )
            return {};

        std::set<const declaration::Parameter*> result;

        for ( const auto& [node, transfer] : cfg->dataflow() ) {
            for ( const auto* decl : transfer.write ) {
                if ( const auto* param = decl->tryAs<declaration::Parameter>() )
                    result.insert(param);
            }

            for ( const auto& [decl, _] : transfer.gen ) {
                if ( const auto* param = decl->tryAs<declaration::Parameter>() )
                    result.insert(param);
            }
        }

        return result;
    }

    /**
     * Helper to extract function parameters from either a function declaration
     * or a field method declaration. If declaration is null, returns an empty
     * set.
     */
    node::Set<type::function::Parameter> functionParameters(const Declaration* decl) {
        if ( ! decl )
            return {};

        if ( const auto* f = decl->tryAs<declaration::Function>() )
            return f->function()->ftype()->parameters();
        else if ( const auto* f = decl->tryAs<declaration::Field>() )
            return f->type()->type()->tryAs<type::Function>()->parameters();
        else
            util::detail::internalError(util::fmt("unexpected prototype node of type '%s'", decl->typename_()));
    }

    /**
     * Records any promotable parameters for a function, considering both the
     * its main definition and any separate prototype declaration if provided.
     */
    void collectPromotable(type::Function* ftype, statement::Block* body, Declaration* prototype = nullptr) {
        auto modified = modifiedParameters(body, state());

        const auto& params = ftype->parameters();
        auto prototype_params = functionParameters(prototype);

        for ( std::size_t i = 0; i < params.size(); ++i ) {
            auto* param = params[i];

            if ( (param->kind() == parameter::Kind::Copy || param->kind() == parameter::Kind::InOut) &&
                 ! modified.contains(param) ) {
                promotable_params.insert(param);

                if ( i < prototype_params.size() && prototype_params[i]->kind() == param->kind() )
                    promotable_params.insert(prototype_params[i]);
            }
        }
    }

    void operator()(declaration::Function* n) final {
        auto function_id = n->functionID(context());
        const auto may_modify = optimizer()->mayModify(n);

        if ( auto* body = n->function()->body(); body && may_modify ) {
            auto* prototype = n->linkedPrototypeIndex() ? context()->lookup(n->linkedPrototypeIndex()) : nullptr;
            collectPromotable(n->function()->ftype(), body, prototype);
        }

        if ( unused_params.contains(function_id) )
            return;

        // Create the unused params
        auto& unused = unused_params[function_id];

        if ( ! may_modify )
            return;

        auto all_lookups = context()->root()->scope()->lookupAll(n->fullyQualifiedID());

        // Don't set if there's no body or multiple implementations
        if ( ! n->function()->body() ||
             (all_lookups.size() > 1 && n->function()->ftype()->flavor() != type::function::Flavor::Hook) )
            return;

        // Don't set if a use may have side effects
        if ( usesContainSideEffects(n->operator_()) )
            return;

        for ( std::size_t i = 0; i < n->function()->ftype()->parameters().size(); i++ )
            // Declare all as unused for now, we'll remove the used ones as we
            // encounter them inside the body.
            unused.push_back(i);
    }

    void operator()(declaration::Field* n) final {
        const auto* ftype = n->type()->type()->tryAs<type::Function>();
        if ( ! ftype || ! n->parent()->isA<type::Struct>() )
            return;

        const auto& function_id = n->fullyQualifiedID();

        if ( unused_params.contains(function_id) )
            return;

        // Create the unused params
        auto& unused = unused_params[function_id];

        if ( ! optimizer()->mayModifyOrRemove(n) )
            return;

        if ( auto* func = n->inlineFunction(); func && func->body() )
            collectPromotable(func->ftype(), func->body());

        // Don't set if a use may have side effects
        if ( usesContainSideEffects(n->operator_()) )
            return;

        for ( std::size_t i = 0; i < ftype->parameters().size(); i++ )
            // Declare all as unused for now, we'll remove the used ones as we
            // encounter them inside the body.
            unused.push_back(i);
    }

    void operator()(expression::Name* n) final {
        auto opt_enclosing_fn = hilti::detail::Optimizer::enclosingFunction(context(), n);
        if ( ! opt_enclosing_fn )
            return;

        auto [func, function_id] = *opt_enclosing_fn;

        auto& unused = unused_params.at(function_id);
        if ( unused.size() == 0 )
            return;

        removeUsed(func->ftype(), function_id, n);
    }
};

/**
 * Optimizes function parameters: removes unused ones and promotes
 * `copy`/`inout` to `in` where possible.
 */
struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const CollectorParameters* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const CollectorParameters* collector = nullptr;

    std::set<const Operator*> processed_operators;
    std::set<type::Function*> processed_functions;

    void removeArgs(expression::ResolvedOperator* call, const std::vector<std::size_t>& positions) {
        assert(call->isA<operator_::function::Call>() || call->isA<operator_::struct_::MemberCall>());

        if ( positions.empty() )
            return;

        bool is_method = call->isA<operator_::struct_::MemberCall>();

        // Get the params as a tuple
        const auto* ctor = is_method ? call->op2()->as<expression::Ctor>() : call->op1()->as<expression::Ctor>();
        const auto* tup = ctor->ctor()->as<ctor::Tuple>();

        // Make new parameters
        Expressions params;
        for ( std::size_t i = 0; i < tup->value().size(); i++ ) {
            if ( std::ranges::find(positions, i) == positions.end() )
                params.push_back(tup->value()[i]);
        }

        auto* ntuple = builder()->expressionCtor(builder()->ctorTuple(params));
        if ( is_method )
            replaceNode(call->op2(), ntuple, "removing unused arguments from method call");
        else
            replaceNode(call->op1(), ntuple, "removing unused arguments from call");
    }

    void pruneFromUses(const ID& function_id, const Operator* op) {
        if ( processed_operators.contains(op) )
            return;

        processed_operators.insert(op);

        const auto& unused = collector->unused_params.at(function_id);
        if ( unused.empty() || ! op )
            return;

        const auto* uses_of_op = collector->collector_callers->uses(op);

        if ( ! uses_of_op )
            return;

        for ( auto* use : *uses_of_op ) {
            if ( use )
                removeArgs(use, unused);
        }
    }

    void pruneFromDecl(const ID& function_id, type::Function* ftype) {
        if ( processed_functions.contains(ftype) )
            return;

        processed_functions.insert(ftype);

        auto unused = collector->unused_params.at(function_id); // copy, so that we can sort below
        if ( unused.empty() )
            return;

        auto params = ftype->parameters();

        // Ensure they're sorted in descending order so we remove from the back.
        std::ranges::sort(unused, std::greater<>());
        for ( std::size_t index : unused ) {
            assert(index < params.size());
            params.erase(params.begin() + static_cast<std::ptrdiff_t>(index));
        }

        recordChange(ftype, "removing unused function parameters");
        ftype->setParameters(builder()->context(), params);
    }

    /**
     * Helper to get a function's call operator from either a function
     * declaration or a field method declaration.
     */
    const auto* functionOperator(const declaration::Parameter* n) {
        if ( auto* func = n->parent<declaration::Function>() )
            return func->operator_();
        else if ( auto* field = n->parent<declaration::Field>() )
            return field->operator_();
        else
            util::detail::internalError(
                util::fmt("unexpected parameter parent of type '%s'", n->parent()->typename_()));
    }

    void operator()(declaration::Function* n) final {
        auto function_id = n->functionID(context());
        pruneFromDecl(function_id, n->function()->ftype());
        pruneFromUses(function_id, n->operator_());
    }

    void operator()(declaration::Field* n) final {
        auto* ftype = n->type()->type()->tryAs<type::Function>();
        if ( ! ftype || ! n->parent()->isA<type::Struct>() )
            return;

        const auto& function_id = n->fullyQualifiedID();
        pruneFromDecl(function_id, ftype);
        pruneFromUses(function_id, n->operator_());
    }

    void operator()(declaration::Parameter* n) final {
        if ( ! collector->promotable_params.contains(n) )
            return;

        auto msg = util::fmt("promoting unmodified '%s' parameter to 'in'", to_string(n->kind()));
        recordChange(n, msg);
        n->setKind(context(), parameter::Kind::In);

        // Promoting parameters can change the call-site CFG dataflow. so we
        // must invalidate the CFG of every function that calls this one.
        const auto* uses = collector->collector_callers->uses(functionOperator(n));
        if ( ! uses )
            return;

        for ( const auto* use : *uses ) {
            if ( auto* f = use->parent<Function>() )
                state()->functionChanged(f);
            else {
                // If the call site is at module level, invalidate the module's
                // CFG instead.
                auto* module = use->parent<hilti::declaration::Module>();
                assert(module);
                state()->moduleChanged(module);
            }
        }
    }
};

bool run(Optimizer* optimizer) {
    CollectorCallers collector_callers(optimizer);
    collector_callers.run();

    CollectorParameters collector(optimizer, &collector_callers);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass optimize_params({.id = PassID::OptimizeParameters,
                                         .guarantees = Guarantees::ConstantsFolded,
                                         .run = run});

} // namespace
