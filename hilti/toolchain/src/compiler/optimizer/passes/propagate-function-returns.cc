// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/collector-callers.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

/** Makes a map from a given use's parameters to the function params. */
std::map<ID, ID> makeParamMap(const ctor::Tuple* tup, const declaration::Parameters& params) {
    auto params_iter = params.begin();
    std::map<ID, ID> param_names;
    for ( auto* val : tup->value() ) {
        if ( auto* name = val->tryAs<expression::Name>() )
            param_names[name->id()] = (*params_iter)->id();

        params_iter++;
    }

    return param_names;
}

/** Gets the field connected to a given function, if any. */
std::optional<const declaration::Field*> getField(ASTContext* ctx, declaration::Function* n) {
    auto* decl = ctx->lookup(n->linkedDeclarationIndex());
    if ( ! decl )
        return {};

    auto* type_decl = decl->tryAs<declaration::Type>();
    if ( ! type_decl )
        return {};

    auto* struct_ = type_decl->type()->type()->tryAs<type::Struct>();
    if ( ! struct_ )
        return {};

    auto* field = struct_->field(n->id().local());
    if ( ! field )
        return {};

    return field;
}

/**
 * Gathers "placements" of a function's parameters. If a function takes
 * a parameter 'x' then only ever returns 'x' in the first element of
 * a tuple, then 'x' will have a placement in index 0. This placement
 * is only set if all uses *also* expect 'x' in index 0.
 *
 * Later, we can use this information to tell that we can remove 'x'
 * from the return, since it is never changed and just returned as-is.
 */
struct CollectorPlacements : public optimizer::visitor::Collector {
    CollectorPlacements(Optimizer* optimizer, const CollectorCallers* operators)
        : optimizer::visitor::Collector(optimizer), collector_callers(operators) {}

    const CollectorCallers* collector_callers;

    struct Placements {
        // The placements for a given function mean which IDs can propagate
        // into the caller. The index indicates which position the use
        // expects a given ID. If the position has an empty optional, then
        // no propagation is possible.
        std::vector<std::optional<ID>> placements;

        // For the passthroughs, imagine three functions:
        //
        // function one(...) : ... { return ...; }
        // function two(...) : ... { return one(...); }
        // function three(...) : ... { let (a, b, c) = two(); }
        //
        // Here, one() is the function we will optimize. It has the
        // 'passthrough' field set to a pointer to two(), as it
        // uses two() as a passthrough. two() has its passthrough_from
        // field set to one(), as one() uses two() as a passthrough.
        // three() is a use.
        Function* passthrough = nullptr;
        Function* passthrough_from = nullptr;
    };

    std::map<ID, Placements> fn_placements; // Function ID to its placements

    // Functions to revisit since their uses didn't have placements
    // calculated yet.
    std::set<declaration::Function*> revisit;

    void run(Node* node = nullptr) override {
        init();
        hilti::visitor::visit(*this, node ? node : context()->root());
        // Revisit the passthroughs that need recalculation
        for ( auto* n : revisit )
            collectFn(n, /*revisiting=*/true);
        done();
    }

    // If one is a passthrough of the other, consolidates the passthroughs.
    void mergePlacements(Placements& self, Placements& other) {
        if ( self.passthrough )
            self.placements = other.placements;
        else
            other.placements = self.placements;
    }

    /**
     * Based on the uses and parameters for the function, this calculates
     * "placements" for the parameters. That is, which uses always
     * assign to the same tuple position. If any use assigns to a different
     * position, then it is not included, and its position is nullopt.
     */
    std::vector<std::optional<ID>> calculatePlacements(const std::vector<expression::ResolvedOperator*>* uses_of_op,
                                                       const declaration::Parameters& params) {
        if ( ! uses_of_op || uses_of_op->empty() )
            return {};

        std::vector<std::optional<ID>> result;
        for ( auto* use : *uses_of_op ) {
            auto is_grouping =
                use->pathMatches<declaration::LocalVariable, expression::Grouping, operator_::tuple::CustomAssign>();
            auto* tup_assign = is_grouping ? use->parent(3)->tryAs<operator_::tuple::CustomAssign>() :
                                             use->parent()->tryAs<operator_::tuple::CustomAssign>();

            // All uses must be tuple assignments
            if ( ! tup_assign )
                return {};

            expression::Ctor* ctor_expr;
            if ( auto* call = use->tryAs<operator_::function::Call>() )
                ctor_expr = call->op1()->tryAs<expression::Ctor>();
            else if ( auto* call = use->tryAs<operator_::struct_::MemberCall>() )
                ctor_expr = call->op2()->tryAs<expression::Ctor>();
            else
                return {};

            if ( ! ctor_expr )
                return {};

            auto* tuple_ctor = ctor_expr->ctor()->tryAs<ctor::Tuple>();
            if ( ! tuple_ctor )
                return {};

            std::map<ID, ID> param_names = makeParamMap(tuple_ctor, params);

            auto* lhs_ctor_expr = tup_assign->op0()->as<expression::Ctor>();
            auto* lhs_tup_ctor = lhs_ctor_expr->ctor()->as<ctor::Tuple>();
            const auto& lhs_values = lhs_tup_ctor->value();
            for ( std::size_t i = 0; i < lhs_values.size(); ++i ) {
                std::optional<ID> entry = {};
                if ( auto* name_node = lhs_values[i]->tryAs<expression::Name>() ) {
                    if ( auto it = param_names.find(name_node->id()); it != param_names.end() )
                        entry = it->second;
                }

                if ( i >= result.size() )
                    result.emplace_back(entry);
                else if ( result[i] != entry )
                    result[i] = {};
            }
        }

        return result;
    }

    void collectFn(declaration::Function* n, bool revisiting) {
        assert(n);
        auto function_id = n->functionID(context());
        const auto* op = n->operator_();

        // If we don't have an operator, grab it from the field.
        if ( ! op ) {
            auto opt_field = getField(context(), n);
            if ( ! opt_field.has_value() )
                logger().internalError(
                    util::fmt("function declaration for %s without a field or operator", function_id));

            op = (*opt_field)->operator_();
            assert(op);
        }

        // Don't visit if we've already calculated placements
        if ( ! revisiting && fn_placements.contains(function_id) )
            return;

        fn_placements.insert({function_id, {}});

        // Don't change public functions
        if ( n->linkage() == declaration::Linkage::Public )
            return;

        auto all_lookups = context()->root()->scope()->lookupAll(n->fullyQualifiedID());

        // Don't change signature if there's no body or multiple implementations
        if ( ! n->function()->body() ||
             (all_lookups.size() > 1 && n->function()->ftype()->flavor() != type::function::Flavor::Hook) )
            return;

        // Make sure this only happens on tuple returns
        if ( ! n->function()->ftype()->result()->type()->isA<type::Tuple>() )
            return;

        const auto* uses_of_op = collector_callers->uses(op);
        if ( ! uses_of_op )
            return;

        auto& placements = fn_placements.at(function_id);
        // First, calculate passthroughs. These are important because they will
        // dictate how the placements are calculated.
        for ( auto* use : *uses_of_op ) {
            if ( auto* ret = use->parent()->tryAs<statement::Return>();
                 ret && placements.passthrough_from == nullptr ) {
                // This is NOT a passthrough, and the use immediately returns.
                // See if we can calculate a passthrough.
                auto opt_enclosing_fn = hilti::detail::Optimizer::enclosingFunction(context(), use);
                if ( ! opt_enclosing_fn )
                    return;

                auto [func, passthrough_function_id] = *opt_enclosing_fn;
                if ( ! fn_placements.contains(passthrough_function_id) ||
                     fn_placements[passthrough_function_id].placements.size() == 0 ) {
                    if ( ! revisiting )
                        revisit.insert(n);

                    return;
                }

                auto& passthrough_placements = fn_placements[passthrough_function_id];
                // Only one passthrough at a time is supported, so if there
                // are multiple, clear both.
                if ( passthrough_placements.passthrough_from &&
                     passthrough_placements.passthrough_from != n->function() ) {
                    passthrough_placements.placements.clear();
                    placements.placements.clear();
                    return;
                }

                // Passthrough must be the same type
                if ( ! type::same(n->function()->ftype()->result(), func->ftype()->result()) ) {
                    passthrough_placements.placements.clear();
                    placements.placements.clear();
                    return;
                }

                // Success, this function passes through the use's function.
                // Mark that.
                placements.passthrough = func;
                passthrough_placements.passthrough_from = n->function();

                // Calculate the passthrough's placements here so we get
                // an accurate one for the future.
                mergePlacements(placements, passthrough_placements);
            }
            else if ( placements.passthrough ) {
                // The use was not a passthrough, or didn't return immediately.
                // So, this shouldn't propagate.
                placements.placements.clear();
                return;
            }
        }

        // Another loop to calculate *this* one's placements, but only if
        // it doesn't have a passthrough.
        if ( ! placements.passthrough && placements.placements.size() == 0 )
            placements.placements = calculatePlacements(uses_of_op, n->function()->ftype()->parameters());

        // Now put placements into its passthrough, if any.
        if ( placements.passthrough_from ) {
            auto* parent = placements.passthrough_from->parent();
            if ( ! parent )
                return;
            auto* fn_decl = parent->tryAs<declaration::Function>();
            if ( ! fn_decl )
                return;
            auto& from_placements = fn_placements[fn_decl->functionID(context())];
            mergePlacements(placements, from_placements);
        }
    }

    void operator()(declaration::Function* n) final { collectFn(n, /*revisiting=*/false); }
};

/**
 * Removes placements if they are used without being immediately returned
 * in a tuple.
 */
struct CollectorPrunePlacements : public optimizer::visitor::Collector {
    CollectorPrunePlacements(Optimizer* optimizer, CollectorPlacements* collector_placements)
        : optimizer::visitor::Collector(optimizer), collector_placements(collector_placements) {}

    CollectorPlacements* collector_placements;

    void operator()(expression::Name* n) final {
        auto opt_enclosing_fn = hilti::detail::Optimizer::enclosingFunction(context(), n);
        if ( ! opt_enclosing_fn )
            return;

        auto [_, function_id] = *opt_enclosing_fn;

        if ( ! collector_placements->fn_placements.contains(function_id) )
            return;

        // There is a very specific hierarchy, potentially coerced:
        //
        // Return
        //   -> Ctor expression
        //     -> tuple ctor
        //       -> this name
        auto is_tup_ret = n->pathMatches<ctor::Tuple, expression::Ctor>();
        auto is_coerced = n->pathMatches<ctor::Tuple, ctor::Coerced, expression::Ctor>();

        if ( is_tup_ret || is_coerced ) {
            // Check the terminal node
            auto* p = is_coerced ? n->parent(4) : n->parent(3);
            if ( p && (p->isA<statement::Return>() || p->isA<operator_::struct_::MemberCall>()) )
                return;
        }

        // Invalidate any placements for this ID since it's not within
        // the hierarchy we are looking for
        auto& placements = collector_placements->fn_placements.at(function_id);
        for ( auto& placement : placements.placements ) {
            if ( placement && *placement == n->id() )
                placement = {};
        }
    }

    // Check to see if we're returning a tuple, and if not, clear placements.
    void operator()(statement::Return* n) final {
        auto opt_enclosing_fn = hilti::detail::Optimizer::enclosingFunction(context(), n);
        if ( ! opt_enclosing_fn )
            return;

        auto [_, function_id] = *opt_enclosing_fn;
        if ( ! collector_placements->fn_placements.contains(function_id) )
            return;
        auto& placements = collector_placements->fn_placements.at(function_id);
        if ( placements.placements.size() == 0 )
            return;

        if ( ! n->expression() ) {
            placements.placements.clear();
            return;
        }

        auto* ctor_expr = n->expression()->tryAs<expression::Ctor>();
        ctor::Tuple* tuple_ctor = nullptr;
        if ( ctor_expr ) {
            // Skip coercion
            if ( auto* coerced = ctor_expr->ctor()->tryAs<ctor::Coerced>() )
                tuple_ctor = coerced->originalCtor()->tryAs<ctor::Tuple>();
            else
                tuple_ctor = ctor_expr->ctor()->tryAs<ctor::Tuple>();
        }

        // We only care about tuple ctors
        if ( ! tuple_ctor ) {
            placements.placements.clear();
            return;
        }

        // Invalidate if name doesn't line up
        for ( std::size_t i = 0; i < placements.placements.size(); i++ ) {
            auto* expr = tuple_ctor->value()[i];
            auto placement = placements.placements[i];
            if ( auto* name = expr->tryAs<expression::Name>(); ! name || (placement && name->id() != *placement) )
                placements.placements[i] = {};
        }
    }
};

/**
 * Propagates the function returns.
 *
 * Given some placement of 'x' in the first element of a tuple, this will:
 *
 *   1) Change the function's return type to not include 'x'
 *   2) Change the field's return type, if a method, to not include 'x'
 *   3) Change all uses to not assign 'x' to the return value of the function
 *   4) Change all returns to not return 'x'
 */
struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, CollectorPlacements* collector_placements)
        : optimizer::visitor::Mutator(optimizer), collector_placements(collector_placements) {}

    CollectorPlacements* collector_placements = nullptr;

    /**
     * Crafts a new return value for function based on which return placements
     * get removed. The caller must ensure placements and tup_ty contain the
     * same number of elements.
     *
     * @param tup_ty the tuple returned by the function
     * @param placements which element IDs are getting removed
     * @return the new return type, possibly unchanged
     */
    QualifiedType* newRet(type::Tuple* tup_ty, const std::vector<std::optional<ID>>& placements) {
        // The caller must check the sizes match
        assert(tup_ty->elements().size() == placements.size());

        QualifiedTypes types;
        for ( std::size_t i = 0; i < placements.size(); ++i ) {
            if ( ! placements[i] )
                types.push_back(tup_ty->elements()[i]->type());
        }

        switch ( types.size() ) {
            case 0: return builder()->qualifiedType(builder()->typeVoid(), Constness::Const);
            case 1: return types[0];
            default: return builder()->qualifiedType(builder()->typeTuple(types), Constness::Const);
        }
    }

    void operator()(declaration::Function* n) final {
        auto function_id = n->functionID(context());

        const auto* op = n->operator_();

        auto opt_field = getField(context(), n);
        if ( ! op ) {
            if ( ! opt_field )
                logger().internalError(
                    util::fmt("function declaration for %s without a field or operator", function_id));
            op = (*opt_field)->operator_();
        }

        if ( ! collector_placements->fn_placements.contains(function_id) )
            return;

        auto& placements = collector_placements->fn_placements.at(function_id);
        auto placement_ids = placements.placements;

        // If it's a passthrough, we get placements from the passthrough'd
        if ( placements.passthrough_from ) {
            auto* parent = placements.passthrough_from->parent();
            if ( ! parent )
                return;
            auto* fn_decl = parent->tryAs<declaration::Function>();
            if ( ! fn_decl )
                return;
            placement_ids = collector_placements->fn_placements[fn_decl->functionID(context())].placements;
        }

        // Make sure at least one placement is getting removed
        if ( ! std::ranges::any_of(placement_ids, [](const std::optional<ID>& opt) { return opt.has_value(); }) )
            return;

        auto* tup_ty = n->function()->ftype()->result()->type()->tryAs<type::Tuple>();
        if ( ! tup_ty || tup_ty->elements().size() != placement_ids.size() )
            return;

        auto* new_ret = newRet(node::deepcopy(context(), tup_ty), placement_ids);
        assert(new_ret);
        replaceNode(n->function()->ftype()->result(), node::deepcopy(context(), new_ret),
                    "propagating new return type");
        // Also need to change field's type
        if ( opt_field ) {
            auto* ftype = (*opt_field)->type()->type()->tryAs<type::Function>();
            if ( ! ftype )
                return;

            replaceNode(ftype->result(), node::deepcopy(context(), new_ret),
                        "propagating new return type to corresponding field");
        }

        const auto* uses_of_op = collector_placements->collector_callers->uses(op);
        if ( ! uses_of_op )
            return;

        for ( auto* use : *uses_of_op ) {
            replaceNode(use->type(), node::deepcopy(context(), new_ret), "propagating return type to use");

            // If this function uses another as a passthrough, only its type
            // gets changed. We do not need to change a tuple assign here.
            if ( placements.passthrough )
                continue;

            // Build map of call args->params
            expression::Ctor* call_ctor_expr = nullptr;
            if ( auto* call = use->tryAs<operator_::function::Call>() )
                call_ctor_expr = call->op1()->tryAs<expression::Ctor>();
            else if ( auto* call = use->tryAs<operator_::struct_::MemberCall>() )
                call_ctor_expr = call->op2()->tryAs<expression::Ctor>();
            else
                return;

            assert(call_ctor_expr);
            auto* call_tuple_ctor = call_ctor_expr->ctor()->as<ctor::Tuple>();

            auto param_names = makeParamMap(call_tuple_ctor, n->function()->ftype()->parameters());

            // Get the tuple ctor
            auto is_grouping =
                use->pathMatches<declaration::LocalVariable, expression::Grouping, operator_::tuple::CustomAssign>();
            auto parent_num = is_grouping ? 3 : 1;
            auto* tup_assign = use->parent(parent_num)->tryAs<operator_::tuple::CustomAssign>();

            auto* tup_ctor = tup_assign->op0()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>();

            Expressions new_tup_assign_exprs;
            if ( tup_ctor->value().size() != placement_ids.size() )
                logger().internalError(
                    util::fmt("function declaration for %s calculated placements incorrectly", function_id));

            auto is_unplaced = [&](auto* expr) {
                auto* name = expr->template tryAs<expression::Name>();
                if ( ! name )
                    return false;

                // Check if the name's ID is NOT in placement_ids
                return std::ranges::find(placement_ids, param_names[name->id()]) == placement_ids.end();
            };

            // Build out the LHS expressions in the replacement
            std::ranges::copy_if(tup_ctor->value(), std::back_inserter(new_tup_assign_exprs), is_unplaced);

            switch ( new_tup_assign_exprs.size() ) {
                // Replace void return with just the call
                case 0:
                    replaceNode(tup_assign, node::deepcopy(context(), use),
                                "removing assignment from propagated return");
                    break;
                case 1:
                    replaceNode(tup_assign, builder()->assign(new_tup_assign_exprs[0], use),
                                "removing tuple from propagated return");
                    break;
                default:
                    replaceNode(tup_assign, builder()->assign(builder()->tuple(new_tup_assign_exprs), use),
                                "removing elements from propagated tuple");
                    break;
            }
        }
    }

    void removeFromTupleCtor(ctor::Tuple* ctor, std::vector<std::optional<ID>> placements) {
        Expressions values;
        int i = 0;
        for ( auto* in_ctor : ctor->value() ) {
            auto* name = in_ctor->tryAs<expression::Name>();

            // If this name is in placements, then we remove it later.
            auto matches_placement = name && (placements[i] == name->id());
            if ( ! matches_placement )
                values.push_back(in_ctor);

            i++;
        }

        // Nothing is removed, do nothing.
        if ( values.size() == ctor->value().size() )
            return;

        Node* to_replace = ctor;

        // Replace coerced ctors too
        while ( to_replace->parent() && to_replace->parent()->isA<ctor::Coerced>() )
            to_replace = to_replace->parent();

        if ( values.size() <= 1 ) {
            // If 0 or 1 values remain, then we remove the tuple ctor. This means
            // that we also have to remove all of the ctors which contained the
            // tuple ctor.
            do {
                to_replace = to_replace->parent();
            } while ( to_replace->parent() &&
                      (to_replace->parent()->isA<expression::Ctor>() || to_replace->parent()->isA<ctor::Coerced>()) );
        }

        switch ( values.size() ) {
            case 0: removeNode(to_replace, "removing now-null return"); break;
            case 1: replaceNode(to_replace, values[0], "propagating return to single element"); break;
            default:
                replaceNode(to_replace, builder()->ctorTuple(values), "propagating return to smaller tuple");
                break;
        }

        ctor->setType(context(), newRet(ctor->type()->type()->as<type::Tuple>(), placements));
    }

    void operator()(statement::Return* n) final {
        auto opt_enclosing_fn = hilti::detail::Optimizer::enclosingFunction(context(), n);
        if ( ! opt_enclosing_fn || ! n->expression() )
            return;

        auto [_, function_id] = *opt_enclosing_fn;
        if ( ! collector_placements->fn_placements.contains(function_id) )
            return;

        auto& placements = collector_placements->fn_placements.at(function_id);

        if ( placements.placements.empty() )
            return;

        auto* ctor_expr = n->expression()->tryAs<expression::Ctor>();
        ctor::Tuple* tuple_ctor = nullptr;
        if ( ctor_expr ) {
            // Skip coercion
            if ( auto* coerced = ctor_expr->ctor()->tryAs<ctor::Coerced>() )
                tuple_ctor = coerced->originalCtor()->tryAs<ctor::Tuple>();
            else
                tuple_ctor = ctor_expr->ctor()->tryAs<ctor::Tuple>();
        }

        // Since we have placements, this should be guaranteed a tuple ctor.
        if ( ! tuple_ctor )
            logger().internalError(util::fmt("function declaration for %s without an operator", function_id),
                                   tuple_ctor);

        removeFromTupleCtor(tuple_ctor, placements.placements);
    }
};


bool run(Optimizer* optimizer) {
    CollectorCallers collector_callers(optimizer);
    collector_callers.run();

    CollectorPlacements collector(optimizer, &collector_callers);
    collector.run();

    CollectorPrunePlacements pruner(optimizer, &collector);
    pruner.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass propagate_function_returns({.id = PassID::PropagateFunctionReturns,
                                                    .guarantees = Guarantees::ConstantsFolded,
                                                    .run = run});

} // namespace
