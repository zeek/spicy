// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

#include "compiler/detail/optimizer/optimizer.h"

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

/** Collects a mapping of all call operators to their uses. */
struct CollectorCallers : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    // Maps the call operator to the places where's been used.
    using Callers = std::map<const Operator*, std::vector<expression::ResolvedOperator*>>;
    Callers callers;

    const Callers::mapped_type* uses(const Operator* x) const {
        if ( ! callers.contains(x) )
            return nullptr;

        return &callers.at(x);
    }

    void operator()(operator_::function::Call* n) final { callers[&n->operator_()].push_back(n); }

    void operator()(operator_::struct_::MemberCall* n) final { callers[&n->operator_()].push_back(n); }
};

/** Collects function parameters not used within the function body. */
struct CollectorUnusedParameters : public optimizer::visitor::Collector {
    CollectorUnusedParameters(Optimizer* optimizer, const CollectorCallers* operators)
        : optimizer::visitor::Collector(optimizer), collector_callers(operators) {}

    const CollectorCallers* collector_callers;

    // The unused parameters for a given function ID
    std::map<ID, std::vector<std::size_t>> unused_params;

    /**
     * Determines if the uses of this operator contain any side effects.
     * Currently, this means a function call that contains another function
     * call as an argument.
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

    std::optional<std::tuple<const type::Function*, ID>> enclosingFunction(const Node* n) const {
        for ( const auto* current = n->parent(); current; current = current->parent() ) {
            if ( const auto* fn_decl = current->tryAs<declaration::Function>() )
                return std::tuple(fn_decl->function()->ftype(), fn_decl->functionID(context()));
            else if ( const auto* field = current->tryAs<declaration::Field>(); field && field->inlineFunction() )
                return std::tuple(field->inlineFunction()->ftype(), field->fullyQualifiedID());
        }

        return {};
    }

    void operator()(declaration::Function* n) final {
        auto function_id = n->functionID(context());

        if ( unused_params.contains(function_id) )
            return;

        // Create the unused params
        auto& unused = unused_params[function_id];

        if ( n->linkage() == declaration::Linkage::Public )
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

        if ( n->attributes()->find(hilti::attribute::kind::Cxxname) ||
             n->attributes()->find(hilti::attribute::kind::AlwaysEmit) ||
             n->attributes()->find(hilti::attribute::kind::Public) )
            return;

        if ( n->linkage() == declaration::Linkage::Public )
            return;

        // If the type is public, we cannot change its fields.
        const auto* type_ = n->parent<declaration::Type>();
        if ( type_ && type_->linkage() == declaration::Linkage::Public )
            return;

        // Don't set if a use may have side effects
        if ( usesContainSideEffects(n->operator_()) )
            return;

        for ( std::size_t i = 0; i < ftype->parameters().size(); i++ )
            // Declare all as unused for now, we'll remove the used ones as we
            // encounter them inside the body.
            unused.push_back(i);
    }

    void operator()(expression::Name* n) final {
        auto opt_enclosing_fn = enclosingFunction(n);
        if ( ! opt_enclosing_fn )
            return;

        auto [ftype, function_id] = *opt_enclosing_fn;

        auto& unused = unused_params.at(function_id);
        if ( unused.size() == 0 )
            return;

        removeUsed(ftype, function_id, n);
    }
};

/** Removes unused function parameters. */
struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const CollectorUnusedParameters* collector_unused_parameters)
        : optimizer::visitor::Mutator(optimizer), collector_unused_parameters(collector_unused_parameters) {}

    const CollectorUnusedParameters* collector_unused_parameters = nullptr;

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

        const auto& unused = collector_unused_parameters->unused_params.at(function_id);
        if ( unused.empty() || ! op )
            return;

        const auto* uses_of_op = collector_unused_parameters->collector_callers->uses(op);

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

        auto unused = collector_unused_parameters->unused_params.at(function_id); // copy, so that we can sort below
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
};

bool run(Optimizer* optimizer) {
    CollectorCallers collector_callers(optimizer);
    collector_callers.run();

    CollectorUnusedParameters collector(optimizer, &collector_callers);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass remove_unused_params({.id = PassID::RemoveUnusedParameters,
                                              .guarantees = Guarantees::ConstantsFolded,
                                              .run = run});

} // namespace
