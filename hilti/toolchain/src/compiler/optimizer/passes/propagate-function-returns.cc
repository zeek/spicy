// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <ranges>

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

#include "ast/ctors/coerced.h"
#include "ast/node-tag.h"
#include "ast/operators/struct.h"
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

// TODO: rename
struct CollectorUnusedParameters : public optimizer::visitor::Collector {
    bool collect_fns = true;

    CollectorUnusedParameters(Optimizer* optimizer, const CollectorCallers* operators)
        : optimizer::visitor::Collector(optimizer), collector_callers(operators) {}

    const CollectorCallers* collector_callers;

    // TODO: This is just copy-pasted from param visitor, fix that.
    std::optional<std::tuple<Function*, ID>> enclosingFunction(Node* n) {
        for ( auto* current = n->parent(); current; current = current->parent() ) {
            if ( auto* fn_decl = current->tryAs<declaration::Function>() ) {
                return std::tuple(fn_decl->function(), fn_decl->functionID(context()));
            }
            else if ( auto* field = current->tryAs<declaration::Field>(); field && field->inlineFunction() ) {
                return std::tuple(field->inlineFunction(), field->fullyQualifiedID());
            }
        }

        return {};
    }

    struct Placements {
        std::vector<std::optional<ID>> placements;
        // TODO: Explain that the passthrough function is the one that *calls* this one
        Function* passthrough = nullptr;      // The function this will passthrough, if any
        Function* passthrough_from = nullptr; // If this is a passthrough, what function is
                                              // it calling
    };

    // TODO: Rename this, idk why I let this get this far misnamed
    std::map<ID, Placements> removeable_params;

    // Functions to revisit since their uses didn't have placements calculated
    // yet.
    std::vector<declaration::Function*> revisit;

    // If one is a passthrough of the other, consolidates the passthroughs.
    void mergePlacements(Placements& self, Placements& other) {
        if ( self.passthrough ) {
            self.placements = other.placements;
        }
        else {
            other.placements = self.placements;
        }
    }


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

    std::vector<std::optional<ID>> calculatePlacements(const std::vector<expression::ResolvedOperator*>* uses_of_op,
                                                       const declaration::Parameters& params) {
        std::vector<std::optional<ID>> result;
        for ( auto* use : *uses_of_op ) {
            // TODO: Look up enclosing function if it's a call, then register
            // passthrough
            auto* tup_assign = use->parent()->tryAs<operator_::tuple::CustomAssign>();
            // All uses must be tuple assignments
            if ( ! tup_assign ) {
                result.clear();
                return result;
            }

            auto* lhs_ctor_expr = tup_assign->op0()->as<expression::Ctor>();
            auto* lhs_tup_ctor = lhs_ctor_expr->ctor()->as<ctor::Tuple>();
            // TODO: These returns need to change
            // TODO: try Methods?
            expression::Ctor* ctor_expr;
            if ( auto* call = use->tryAs<operator_::function::Call>() )
                ctor_expr = call->op1()->tryAs<expression::Ctor>();
            else if ( auto* call = use->tryAs<operator_::struct_::MemberCall>() )
                ctor_expr = call->op2()->tryAs<expression::Ctor>();
            else
                return result;
            // TODO: Clear results if returning early?

            if ( ! ctor_expr )
                return result;
            auto* tuple_ctor = ctor_expr->ctor()->tryAs<ctor::Tuple>();
            if ( ! tuple_ctor )
                return result;

            std::map<ID, ID> param_names = makeParamMap(tuple_ctor, params);
            for ( std::size_t i = 0; i < lhs_tup_ctor->value().size(); i++ ) {
                auto* val = lhs_tup_ctor->value()[i];
                auto* name = val->tryAs<expression::Name>();

                // Add the name if one isn't in this position
                if ( result.size() <= i ) {
                    if ( name )
                        result.emplace_back(param_names[name->id()]);
                    else
                        result.emplace_back();
                }
                else if ( ! name || (result[i] && param_names[name->id()] != *result[i]) ) {
                    // Invalidate this entry if this isn't a name or this
                    // one's param doesn't match what was there before
                    result[i] = {};
                }
            }
        }

        return result;
    }

    void operator()(declaration::Function* n) final {
        if ( ! collect_fns )
            return;
        auto function_id = n->functionID(context());

        const auto* op = n->operator_();
        declaration::Field* field = nullptr;
        if ( ! op ) {
            auto* decl = context()->lookup(n->linkedDeclarationIndex());
            if ( ! decl )
                return;
            auto* type_decl = decl->tryAs<declaration::Type>();
            if ( ! type_decl )
                return;
            auto* struct_ = type_decl->type()->type()->tryAs<type::Struct>();
            if ( ! struct_ )
                return;
            // TODO: This is silly man. Why use local?
            field = struct_->field(function_id.local());
            if ( ! field )
                return;
            op = field->operator_();
        }

        // TODO: Remember to rename placements and removable_params! :)
        // Create the removeable placements
        if ( removeable_params[function_id].placements.size() > 0 )
            return;

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

        auto& placements = removeable_params.at(function_id);
        for ( auto* use : *uses_of_op ) {
            // If this isn't a passthrough, then the use can be a passthrough
            if ( auto* ret = use->parent()->tryAs<statement::Return>();
                 ret && placements.passthrough_from == nullptr ) {
                auto opt_enclosing_fn = enclosingFunction(use);
                if ( ! opt_enclosing_fn )
                    return;

                auto [func, function_id] = *opt_enclosing_fn;
                if ( ! removeable_params.contains(function_id) ||
                     removeable_params[function_id].placements.size() == 0 ) {
                    revisit.push_back(n);
                    return;
                }

                auto& passthrough_placements = removeable_params[function_id];
                // If it's already a passthrough from something that's not this, clear it and this.
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

                placements.passthrough = func;
                passthrough_placements.passthrough_from = n->function();
                if ( passthrough_placements.placements.size() == 0 ) {
                    // TODO: This is silly, it's just copy-pasted from above.
                    // and kind of below. We need the field's operator if
                    // it's a field, but even without that we don't have the
                    // decl....
                    //
                    // We can maybe change enclosingFunction here. But it
                    // needs to *still* account for the operator being null.
                    // ugh.
                    auto* parent = func->parent();
                    if ( ! parent )
                        return;
                    auto* fn_decl = parent->tryAs<declaration::Function>();
                    if ( ! fn_decl )
                        return;
                    const auto* op = n->operator_();
                    declaration::Field* field = nullptr;
                    if ( ! op ) {
                        auto* decl = context()->lookup(fn_decl->linkedDeclarationIndex());
                        if ( ! decl )
                            return;
                        auto* type_decl = decl->tryAs<declaration::Type>();
                        if ( ! type_decl )
                            return;
                        auto* struct_ = type_decl->type()->type()->tryAs<type::Struct>();
                        if ( ! struct_ )
                            return;
                        // TODO: This is silly man. Why use local?
                        field = struct_->field(function_id.local());
                        if ( ! field )
                            return;
                        op = field->operator_();
                    }
                    const auto* uses_of_passthrough = collector_callers->uses(op);
                    if ( ! uses_of_passthrough )
                        return;
                    passthrough_placements.placements =
                        calculatePlacements(uses_of_passthrough, func->ftype()->parameters());
                }
                // Calculate the passthrough's placements here so we get
                // an accurate one for the future.
                mergePlacements(placements, passthrough_placements);

                continue;
            }

            // If this passthroughs another function and gets here we clear
            if ( placements.passthrough ) {
                placements.placements.clear();
                return;
            }
        }

        if ( ! placements.passthrough && placements.placements.size() == 0 )
            placements.placements = calculatePlacements(uses_of_op, n->function()->ftype()->parameters());

        // Now put placements into its passthrough, if any.
        if ( placements.passthrough_from ) {
            // TODO: This needs to map the passthrough's params to the
            // passthrough'd
            auto* parent = placements.passthrough_from->parent();
            if ( ! parent )
                return;
            auto* fn_decl = parent->tryAs<declaration::Function>();
            if ( ! fn_decl )
                return;
            auto& from_placements = removeable_params[fn_decl->functionID(context())];
            mergePlacements(placements, from_placements);
        }
    }

    void doRevisits() {
        for ( auto* n : revisit ) {
            auto function_id = n->functionID(context());

            const auto* op = n->operator_();
            declaration::Field* field = nullptr;
            if ( ! op ) {
                auto* decl = context()->lookup(n->linkedDeclarationIndex());
                if ( ! decl )
                    return;
                auto* type_decl = decl->tryAs<declaration::Type>();
                if ( ! type_decl )
                    return;
                auto* struct_ = type_decl->type()->type()->tryAs<type::Struct>();
                if ( ! struct_ )
                    return;
                // TODO: This is silly man. Why use local?
                field = struct_->field(function_id.local());
                if ( ! field )
                    return;
                op = field->operator_();
            }

            // Create the removeable placements
            if ( removeable_params[function_id].placements.size() > 0 )
                return;

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

            auto& placements = removeable_params.at(function_id);
            for ( auto* use : *uses_of_op ) {
                // If this isn't a passthrough, then the use can be a passthrough
                if ( auto* ret = use->parent()->tryAs<statement::Return>();
                     ret && placements.passthrough_from == nullptr ) {
                    auto opt_enclosing_fn = enclosingFunction(use);
                    if ( ! opt_enclosing_fn )
                        return;

                    auto [func, function_id] = *opt_enclosing_fn;
                    if ( ! removeable_params.contains(function_id) ) {
                        revisit.push_back(n);
                        return;
                    }

                    auto& passthrough_placements = removeable_params[function_id];
                    // If it's already a passthrough from something that's not this, clear it and this.
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

                    placements.passthrough = func;
                    passthrough_placements.passthrough_from = n->function();
                    if ( passthrough_placements.placements.size() == 0 ) {
                        // TODO: This is silly, it's just copy-pasted from above.
                        // and kind of below. We need the field's operator if
                        // it's a field, but even without that we don't have the
                        // decl....
                        //
                        // We can maybe change enclosingFunction here. But it
                        // needs to *still* account for the operator being null.
                        // ugh.
                        auto* parent = func->parent();
                        if ( ! parent )
                            return;
                        auto* fn_decl = parent->tryAs<declaration::Function>();
                        if ( ! fn_decl )
                            return;
                        const auto* op = n->operator_();
                        declaration::Field* field = nullptr;
                        if ( ! op ) {
                            auto* decl = context()->lookup(fn_decl->linkedDeclarationIndex());
                            if ( ! decl )
                                return;
                            auto* type_decl = decl->tryAs<declaration::Type>();
                            if ( ! type_decl )
                                return;
                            auto* struct_ = type_decl->type()->type()->tryAs<type::Struct>();
                            if ( ! struct_ )
                                return;
                            // TODO: This is silly man. Why use local?
                            field = struct_->field(function_id.local());
                            if ( ! field )
                                return;
                            op = field->operator_();
                        }
                        const auto* uses_of_passthrough = collector_callers->uses(op);
                        if ( ! uses_of_passthrough )
                            return;
                        passthrough_placements.placements =
                            calculatePlacements(uses_of_passthrough, func->ftype()->parameters());
                    }
                    // Calculate the passthrough's placements here so we get
                    // an accurate one for the future.
                    mergePlacements(placements, passthrough_placements);

                    continue;
                }

                // If this passthroughs another function and gets here we clear
                if ( placements.passthrough ) {
                    placements.placements.clear();
                    return;
                }
            }

            if ( ! placements.passthrough && placements.placements.size() == 0 )
                placements.placements = calculatePlacements(uses_of_op, n->function()->ftype()->parameters());

            // Now put placements into its passthrough, if any.
            if ( placements.passthrough_from ) {
                // TODO: This needs to map the passthrough's params to the
                // passthrough'd
                auto* parent = placements.passthrough_from->parent();
                if ( ! parent )
                    return;
                auto* fn_decl = parent->tryAs<declaration::Function>();
                if ( ! fn_decl )
                    return;
                auto& from_placements = removeable_params[fn_decl->functionID(context())];
                mergePlacements(placements, from_placements);
            }
        }
    }

    void operator()(expression::Name* n) final {
        // TODO: Using name in returned function call in passthrough is ok
        auto opt_enclosing_fn = enclosingFunction(n);
        if ( ! opt_enclosing_fn )
            return;

        auto [_, function_id] = *opt_enclosing_fn;

        if ( ! removeable_params.contains(function_id) )
            return;

        // There is a very specific hierarchy:
        //
        // Return
        //   -> Ctor expression
        //     -> tuple ctor
        //       -> this name
        bool is_tup_ret =  n->parent()->isA<ctor::Tuple>() && n->parent(2)->isA<expression::Ctor>() &&
             (n->parent(3)->isA<statement::Return>() || n->parent(3)->isA<operator_::struct_::MemberCall>()); 
        bool is_coerced_tup_ret =  n->parent()->isA<ctor::Tuple>() && n->parent(2)->isA<ctor::Coerced>() && n->parent(3)->isA<expression::Ctor>() && 
             (n->parent(4)->isA<statement::Return>() || n->parent(4)->isA<operator_::struct_::MemberCall>()); 
        if (is_tup_ret || is_coerced_tup_ret)
            return;

        // Invalidate any placements for this ID since it's not within
        // the hierarchy we are looking for
        auto& placements = removeable_params.at(function_id);
        for ( auto& placement : placements.placements ) {
            if ( placement && *placement == n->id() )
                placement = {};
        }
    }

    void operator()(statement::Return* n) final {
        // TODO: It's ok to return a call if this is a passthrough, jut return if so?
        // Actually maybe we can just do nothing
        auto opt_enclosing_fn = enclosingFunction(n);
        if ( ! opt_enclosing_fn )
            return;

        auto [_, function_id] = *opt_enclosing_fn;
        if ( ! n->expression() )
            return;
        auto* ctor_expr = n->expression()->tryAs<expression::Ctor>();
        ctor::Tuple* tuple_ctor = nullptr;

        if ( ctor_expr ) {
            // Skip coercion
            if (ctor_expr->ctor()->isA<ctor::Coerced>() )
                tuple_ctor = ctor_expr->ctor()->as<ctor::Coerced>()->originalCtor()->tryAs<ctor::Tuple>();
            else 
                tuple_ctor = ctor_expr->ctor()->tryAs<ctor::Tuple>();
        }

        if ( ! removeable_params.contains(function_id) )
            return;

        auto& placements = removeable_params.at(function_id);
        if ( ! tuple_ctor ) {
            placements.placements.clear();
            return;
        }

        // In the return, we check to see if the placements line up.
        // If not, we cannot remove the parameter.
        // This should never happen
        if ( placements.placements.size() != tuple_ctor->value().size() ) {
            placements.placements.clear();
            return;
        }

        for ( std::size_t i = 0; i < placements.placements.size(); i++ ) {
            auto* expr = tuple_ctor->value()[i];
            auto placement = placements.placements[i];
            if ( auto* name = expr->tryAs<expression::Name>(); ! name || (placement && name->id() != *placement) ) {
                placements.placements[i] = {};
            }
        }
    }
};

/** Removes unused function parameters. */
struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, CollectorUnusedParameters* collector_unused_parameters)
        : optimizer::visitor::Mutator(optimizer), collector_unused_parameters(collector_unused_parameters) {}

    CollectorUnusedParameters* collector_unused_parameters = nullptr;

    // TODO: Dedup this
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


    /**
     * Crafts a new return value for func based on which return placements get
     * removed. The caller must ensure placements and tup_ty contain the same
     * number of elements.
     *
     * @param tup_ty the tuple returned by the function
     * @param placements which element IDs are getting removed
     * @return the new return type, possibly unchanged
     */
    QualifiedType* newRet(type::Tuple* tup_ty, const std::vector<std::optional<ID>>& placements) {
        QualifiedTypes types;
        // The caller must check the sizes match
        assert(tup_ty->elements().size() == placements.size());

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
        declaration::Field* field = nullptr;
        if ( ! op ) {
            auto* decl = context()->lookup(n->linkedDeclarationIndex());
            if ( ! decl )
                return;
            auto* type_decl = decl->tryAs<declaration::Type>();
            if ( ! type_decl )
                return;
            auto* struct_ = type_decl->type()->type()->tryAs<type::Struct>();
            if ( ! struct_ )
                return;
            // TODO: This is silly man. Why use local?
            field = struct_->field(function_id.local());
            if ( ! field )
                return;
            op = field->operator_();
        }
        if ( ! collector_unused_parameters->removeable_params.contains(function_id) )
            return;

        auto& placements = collector_unused_parameters->removeable_params.at(function_id);
        auto placement_ids = placements.placements;
        // If it's a passthrough, we get placements from the passthrough'd
        if ( placements.passthrough_from ) {
            // Get the operator
            // TODO I think this is bad :) It doesn't apply to methods.
            auto* parent = placements.passthrough_from->parent();
            if ( ! parent )
                return;
            auto* fn_decl = parent->tryAs<declaration::Function>();
            if ( ! fn_decl )
                return;
            placement_ids = collector_unused_parameters->removeable_params[fn_decl->functionID(context())].placements;
        }
        // Make sure at least one placement is getting removed
        if ( ! std::ranges::any_of(placement_ids, [](const std::optional<ID>& opt) { return opt.has_value(); }) )
            return;

        auto* tup_ty = n->function()->ftype()->result()->type()->tryAs<type::Tuple>();
        if ( ! tup_ty || tup_ty->elements().size() != placement_ids.size() )
            return;

        replaceNode(n->function()->ftype()->result(), newRet(node::deepcopy(context(), tup_ty), placement_ids));
        // Also need to change field's type
        if ( field ) {
            auto* ftype = field->type()->type()->tryAs<type::Function>();
            if ( ! ftype )
                return;
            // TODO: Don't double-call newRet
            replaceNode(ftype->result(), newRet(node::deepcopy(context(), tup_ty), placement_ids));
        }
        if ( ! collector_unused_parameters->removeable_params.contains(function_id) )
            return;

        // If it's a passthrough, we get placements from the passthrough'd
        if ( placements.passthrough_from ) {
            // Get the operator
            // TODO I think this is bad :) It doesn't apply to methods.
            auto* parent = placements.passthrough_from->parent();
            if ( ! parent )
                return;
            auto* fn_decl = parent->tryAs<declaration::Function>();
            if ( ! fn_decl )
                return;
            placement_ids = collector_unused_parameters->removeable_params[fn_decl->functionID(context())].placements;
        }
        // Make sure at least one placement is getting removed
        if ( ! std::ranges::any_of(placement_ids, [](const std::optional<ID>& opt) { return opt.has_value(); }) )
            return;

        if ( ! tup_ty || tup_ty->elements().size() != placement_ids.size() )
            return;
        auto* new_ret = newRet(tup_ty, placement_ids);
        assert(new_ret);

        const auto* uses_of_op = collector_unused_parameters->collector_callers->uses(op);
        if ( ! uses_of_op )
            return;

        for ( auto* use : *uses_of_op ) {
            replaceNode(use->type(), node::deepcopy(context(), new_ret));

            // Passthroughs only change the use's type
            if ( placements.passthrough )
                continue;

            // Build map of call args->params
            expression::Ctor* call_ctor_expr;
            if ( auto* call = use->tryAs<operator_::function::Call>() )
                call_ctor_expr = call->op1()->tryAs<expression::Ctor>();
            else if ( auto* call = use->tryAs<operator_::struct_::MemberCall>() )
                call_ctor_expr = call->op2()->tryAs<expression::Ctor>();
            else
                return;
            auto* call_tuple_ctor = call_ctor_expr->ctor()->as<ctor::Tuple>();
            auto param_names = makeParamMap(call_tuple_ctor, n->function()->ftype()->parameters());
            // This is guaranteed
            // TODO: Do this better
            auto* tup_assign = use->parent()->as<operator_::tuple::CustomAssign>();
            auto* ctor_expr = tup_assign->op0()->as<expression::Ctor>();
            auto* tup_ctor = ctor_expr->ctor()->as<ctor::Tuple>();
            Expressions new_tup_assign_exprs;
            if ( tup_ctor->value().size() != placement_ids.size() )
                return;
            for ( std::size_t i = 0; i < tup_ctor->value().size(); i++ ) {
                auto* name = tup_ctor->value()[i]->tryAs<expression::Name>();
                if ( ! name )
                    continue;
                if ( std::ranges::find(placement_ids, param_names[name->id()]) == placement_ids.end() )
                    new_tup_assign_exprs.push_back(tup_ctor->value()[i]);
            }

            expression::ResolvedOperator* new_use;
            switch ( new_tup_assign_exprs.size() ) {
                case 0:
                    new_use = node::deepcopy(context(), use);
                    replaceNode(tup_assign, new_use);
                    break;
                case 1: {
                    // Replace the *parent* since that has the ctor
                    auto* assign = builder()->assign(new_tup_assign_exprs[0], use);
                    replaceNode(tup_assign, assign);
                    new_use = assign->source()->as<expression::ResolvedOperator>();
                    break;
                }
                default:
                    auto* assign = builder()->assign(builder()->tuple(new_tup_assign_exprs), use);
                    replaceNode(tup_assign, assign);
                    new_use = assign->source()->as<expression::ResolvedOperator>();
                    break;
            }

            // Since the use was replaced, we have to invalidate it in
            // favor of the new use.
            // TODO: This isn't necessary, right?
            // replaceUse(op, use, new_use);
        }
    }

    void removeFromTupleCtor(ctor::Tuple* ctor, std::vector<std::optional<ID>> placements) {
        Expressions values;
        int i = 0;
        for ( auto* in_ctor : ctor->value() ) {
            if ( auto* name = in_ctor->tryAs<expression::Name>() ) {
                if ( *placements[i] == name->id() ) {
                    i++;
                    continue;
                }
            }
            values.push_back(in_ctor);
            i++;
        }

        // Nothing is removed, do nothing.
        if ( values.size() == ctor->value().size() )
            return;

        switch ( values.size() ) {
            // TODO: message
            case 0: removeNode(ctor->parent(), "Removed"); break;
            case 1:
                // Replace the *parent* since that has the ctor
                replaceNode(ctor->parent(), values[0]);
                break;
            default: replaceNode(ctor, builder()->ctorTuple(values)); break;
        }

        ctor->setType(context(), newRet(ctor->type()->type()->as<type::Tuple>(), placements));
    }

    void operator()(statement::Return* n) final {
        // TODO: It's ok to return a call if this is a passthrough, jut return if so?
        // Actually maybe we can just do nothing
        auto opt_enclosing_fn = collector_unused_parameters->enclosingFunction(n);
        if ( ! opt_enclosing_fn )
            return;

        auto [_, function_id] = *opt_enclosing_fn;
        if ( ! n->expression() )
            return;
        auto* ctor_expr = n->expression()->tryAs<expression::Ctor>();
        ctor::Tuple* tuple_ctor = nullptr;

        auto is_coerced = false;
        if ( ctor_expr ) {
            // Skip coercion
            if (ctor_expr->ctor()->isA<ctor::Coerced>() ) {
                is_coerced = true;
                tuple_ctor = ctor_expr->ctor()->as<ctor::Coerced>()->originalCtor()->tryAs<ctor::Tuple>();
            } else 
                tuple_ctor = ctor_expr->ctor()->tryAs<ctor::Tuple>();
        }

        if ( ! collector_unused_parameters->removeable_params.contains(function_id) )
            return;

        // Only prune tuples
        auto& placements = collector_unused_parameters->removeable_params.at(function_id);
        if ( ! tuple_ctor )
            return;

        if ( ! placements.placements.empty() )
            removeFromTupleCtor(tuple_ctor, placements.placements);

        
        if (is_coerced) {
            // If it's a coercion, we need to replace the coercion as well.
            replaceNode(tuple_ctor->parent(), tuple_ctor, "Uncoercing changed tuple");
        }
    }
};


bool run(Optimizer* optimizer) {
    CollectorCallers collector_callers(optimizer);
    collector_callers.run();

    CollectorUnusedParameters collector(optimizer, &collector_callers);
    collector.run();
    // TODO: This is weird. It's a hack in case a passthrough is analyzed
    // before the function it passthrough_from's (or something like that).
    collector.doRevisits();
    collector.collect_fns = false;
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass propagate_function_returns({.id = PassID::PropagateFunctionReturns,
                                                    .guarantees = Guarantees::ConstantsFolded,
                                                    .run = run});

} // namespace
