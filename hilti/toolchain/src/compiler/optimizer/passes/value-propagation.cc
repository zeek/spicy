// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/cfg.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

struct ReachingValue {
    Expression* expr = nullptr;
    bool propagate = false; // True if it may be propagated

    bool operator==(const ReachingValue& other) const {
        // If neither should propagate, what's in expr doesn't matter
        if ( ! propagate && ! other.propagate )
            return true;

        return expr == other.expr && propagate == other.propagate;
    }
};

using PropagationMap = std::map<Declaration*, ReachingValue>;

struct AnalysisResult {
    std::map<cfg::GraphNode, PropagationMap> in;
    std::map<cfg::GraphNode, PropagationMap> out;
};

// Marks any sources on a modified decl as also unavailable. This is necessary
// with copy propagation if there is an assignment to the to-be-propagated value
// between the initial copy and use (like if storing an old value then modifying
// the new one).
void invalidateDependencies(const Declaration* modified_decl, PropagationMap* reaching_copies) {
    // We could also make a new map of decl->names, but this seems
    // reasonable unless efficiency becomes a concern.
    for ( auto& [decl, value] : *reaching_copies ) {
        if ( ! value.propagate )
            continue;

        if ( const auto* name = value.expr->tryAs<expression::Name>() ) {
            if ( name->resolvedDeclaration() == modified_decl )
                value.propagate = false;
        }
    }
}

// Marks all children that are names as not propagatable in the given map.
// This is used when a name might be nested in various operators and we
// must clear all propagate flags.
struct Invalidator : optimizer::visitor::Collector {
    Invalidator(Optimizer* optimizer, PropagationMap* reaching_copies)
        : optimizer::visitor::Collector(optimizer), reaching_copies(reaching_copies) {}

    PropagationMap* reaching_copies;

    void operator()(expression::Name* name) override {
        if ( auto* decl = name->resolvedDeclaration() ) {
            invalidateDependencies(decl, reaching_copies);
            (*reaching_copies)[decl].propagate = false;
        }
    }
};

struct TransferVisitor : optimizer::visitor::Collector {
    TransferVisitor(Optimizer* optimizer, PropagationMap* reaching_copies)
        : optimizer::visitor::Collector(optimizer),
          reaching_copies(reaching_copies),
          invalidator(optimizer, reaching_copies) {}

    PropagationMap* reaching_copies;
    Invalidator invalidator;

    // Tries to resolve an expression to a known reaching value via the propagation map.
    Expression* resolveValue(Expression* expr) {
        if ( expr->isConstant() && expr->isA<expression::Ctor>() )
            return expr;

        if ( const auto* name = expr->tryAs<expression::Name>() ) {
            if ( auto* decl = name->resolvedDeclaration(); decl && reaching_copies->contains(decl) ) {
                const auto& val = reaching_copies->at(decl);
                if ( ! val.propagate )
                    return expr;

                if ( val.expr ) {
                    // Recurse to try and limit dependency chains of names
                    auto* simplified = resolveValue(val.expr);
                    return simplified ? simplified : val.expr;
                }
            }

            return expr;
        }

        return nullptr;
    }

    void operator()(expression::Assign* assign) override {
        if ( const auto* name = assign->target()->tryAs<expression::Name>() ) {
            if ( auto* decl = name->resolvedDeclaration() ) {
                invalidateDependencies(decl, reaching_copies);
                auto* source_expr = resolveValue(assign->source());
                (*reaching_copies)[decl] = {.expr = source_expr, .propagate = (source_expr != nullptr)};
            }
        }
    }

    void operator()(declaration::LocalVariable* decl) override {
        if ( auto* init = decl->init() ) {
            auto* source_expr = resolveValue(init);
            (*reaching_copies)[decl] = {.expr = source_expr, .propagate = (source_expr != nullptr)};
        }
    }

    /** Marks mutable arguments to a function as not propagatable. */
    void taintMutableArgs(const node::Range<Expression> args, type::Function* ft) {
        assert(args.size() == ft->parameters().size());

        // Do not propagate any inout arguments or aliasing types.
        for ( const auto [i, operand] : util::enumerate(ft->parameters()) ) {
            if ( operand->kind() == hilti::parameter::Kind::InOut || operand->type()->type()->isAliasingType() )
                invalidator.run(args[i]);
        }
    }

    void operator()(operator_::struct_::MemberCall* n) override {
        const auto& op = static_cast<const struct_::MemberCall&>(n->operator_());
        auto* fdecl = op.declaration();
        auto* ft = fdecl->type()->type()->as<type::Function>();
        auto args = n->op2()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();
        taintMutableArgs(args, ft);
    }

    void operator()(operator_::function::Call* n) override {
        auto* decl = context()->lookup(n->op0()->as<expression::Name>()->resolvedDeclarationIndex());
        auto* fdecl = decl->as<declaration::Function>();
        auto* ft = fdecl->function()->type()->type()->as<type::Function>();
        auto args = n->op1()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();
        taintMutableArgs(args, ft);
    }

    void operator()(expression::ResolvedOperator* op) override {
        const auto& sig = op->operator_().signature();

        std::size_t i = 0;
        for ( const auto* operand : sig.operands->operands() ) {
            if ( operand->kind() == parameter::Kind::InOut )
                // Avoid propagating inout parameters.
                invalidator.run(op->operands()[i]);

            i++;
        }
    }
};

struct Replacer : optimizer::visitor::Mutator {
    Replacer(Optimizer* optimizer, const CFG* cfg, const AnalysisResult& result)
        : optimizer::visitor::Mutator(optimizer), cfg(cfg), result(result) {}

    const CFG* cfg;
    const AnalysisResult& result;

    // Helper to find the CFG node for an AST node.
    const cfg::GraphNode* findCFGNode(Node* n) {
        for ( const auto* p = n; p; p = p->parent() ) {
            if ( const auto* graph_node = cfg->graph().getNode(p->identity()) )
                return graph_node;
        }

        return nullptr;
    }

    bool isLHSOfAssign(Expression* expr) {
        for ( auto* parent = expr->parent(); parent; parent = parent->parent() ) {
            // Don't propagate to the LHS of an assignment
            if ( const auto* assign = parent->tryAs<operator_::tuple::CustomAssign>() ) {
                if ( assign->op0() == expr )
                    return true;
            }

            if ( const auto* assign = parent->tryAs<expression::Assign>() ) {
                if ( assign->target() == expr )
                    return true;
            }
        }

        return false;
    }

    void operator()(expression::Name* n) override {
        if ( isLHSOfAssign(n) )
            return;

        const auto* cfg_node = findCFGNode(n);
        if ( ! cfg_node )
            return;

        auto in_it = result.in.find(*cfg_node);
        auto out_it = result.out.find(*cfg_node);
        if ( in_it == result.in.end() || out_it == result.out.end() )
            return;

        auto* decl = n->resolvedDeclaration();
        if ( ! decl )
            return;

        const auto& reaching_copies = in_it->second;
        const auto& out_reaching_copies = out_it->second;
        auto const_it = reaching_copies.find(decl);
        auto out_const_it = out_reaching_copies.find(decl);
        if ( const_it == reaching_copies.end() || out_const_it == out_reaching_copies.end() )
            return;

        // If they aren't the same, something changed within the statement.
        // Since we're not sure which comes first, just abort.
        if ( const_it->second != out_const_it->second )
            return;

        auto source_expr = const_it->second;

        if ( source_expr.propagate ) {
            Node* to_replace = n;
            // Replace the coercion, too, so that the coercer reruns.
            if ( auto* coerced = n->parent()->tryAs<expression::Coerced>() )
                to_replace = coerced;

            replaceNode(to_replace, source_expr.expr, "propagating constant value");
        }
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer) : optimizer::visitor::Mutator(optimizer) {}

    std::map<Node*, AnalysisResult> analysis_results;

    void transfer(const CFG& cfg, const cfg::GraphNode& n, PropagationMap& new_out) {
        // For copy propagation, we need to make sure the value is in scope.
        if ( n->isA<cfg::End>() ) {
            const auto& transfer = cfg.dataflow().at(n);
            for ( auto&& [decl, _] : transfer.kill ) {
                invalidateDependencies(decl, &new_out);
                new_out.erase(decl);
            }
        }

        TransferVisitor(optimizer(), &new_out).run(n.get());
    }

    void populateDataflow(AnalysisResult& result, const PropagationMap& init, const declaration::Function* function) {
        const auto* cfg = state()->cfgCache()->get(function->function()->body());
        assert(cfg);

        auto worklist = cfg->postorder();

        // We always expect the worklist to contain begin/end nodes
        assert(worklist.size() >= 1);

        // Reverse postorder is best for forward analyses
        std::ranges::reverse(worklist);

        // Set the initial state from parameters
        result.out[worklist.front()] = init;
        worklist.pop_front();

        auto num_processed = 0;

        while ( ! worklist.empty() ) {
            auto n = worklist.front();
            worklist.pop_front();

            // Meet
            PropagationMap new_in;

            for ( auto pred : cfg->graph().neighborsUpstream(n->identity()) ) {
                const auto* cfg_node = cfg->graph().getNode(pred);

                // cfg_node was retrieved from the graph itself so should be present.
                assert(cfg_node);
                auto filtered_pred_out = result.out[*cfg_node];

                for ( const auto& [decl, source_expr] : filtered_pred_out ) {
                    // Add if we can, otherwise only propagate if they're
                    // the same const.
                    auto [found, inserted] = new_in.try_emplace(decl, source_expr);
                    if ( ! inserted && found->second != source_expr )
                        found->second.propagate = false;
                }
            }

            result.in[n] = std::move(new_in);

            // Transfer
            PropagationMap new_out = result.in[n];
            transfer(*cfg, n, new_out);

            // If it changed, add successors to worklist
            PropagationMap old_out = result.out[n];

            if ( old_out != new_out ) {
                result.out[n] = std::move(new_out);

                for ( auto succ_id : cfg->graph().neighborsDownstream(n->identity()) ) {
                    const auto* succ_node = cfg->graph().getNode(succ_id);
                    assert(succ_node);

                    if ( std::ranges::find(worklist, *succ_node) == worklist.end() )
                        worklist.push_back(*succ_node);
                }
            }

            num_processed++;
        }

        HILTI_DEBUG(logging::debug::OptimizerPasses,
                    util::fmt("function %s took %d iterations before constant propagation convergence", function->id(),
                              num_processed));
    }

    void propagateFunctionReturn(const CFG* cfg, statement::Block* block) {
        // Get the last statement, this should be a return.
        auto stmts = block->statements();
        auto it = stmts.rbegin();
        if ( it == stmts.rend() || ! (*it)->isA<statement::Return>() )
            return;
        auto* ret = (*it)->as<statement::Return>();
        if ( ! ret->expression() )
            return;

        // Skip coercions
        auto* maybe_coerced = ret->expression();
        while ( maybe_coerced->isA<expression::Coerced>() )
            maybe_coerced = maybe_coerced->as<expression::Coerced>()->expression();

        // Only apply if it's return <name>;
        auto* name = maybe_coerced->tryAs<expression::Name>();
        if ( ! name )
            return;

        auto upstream = cfg->graph().neighborsUpstream(ret->identity());
        if ( upstream.size() != 1 )
            return;
        const auto* prev_node = cfg->graph().getNode(upstream[0]);
        assert(prev_node);

        auto* stmt = prev_node->get()->tryAs<statement::Expression>();
        if ( ! stmt || ! stmt->expression()->isA<expression::Assign>() )
            return;
        auto* name_decl = name->resolvedDeclaration();

        if ( ! cfg->dataflow().contains(*prev_node) )
            return;

        // The previous node must overwrite the decl and it's not an alias.
        auto dataflow_facts = cfg->dataflow().at(*prev_node);
        if ( ! dataflow_facts.gen.contains(name_decl) || ! dataflow_facts.kill.contains(name_decl) ||
             dataflow_facts.maybe_alias.contains(name_decl) )
            return;

        auto* assign = stmt->expression()->as<expression::Assign>();
        replaceNode(ret->expression(), assign->source());
        removeNode(prev_node->get(), "Removing variable propagated to return");
    }

    void applyPropagation(const declaration::Function* function, const AnalysisResult& result) {
        auto* body = function->function()->body();
        const auto* cfg = state()->cfgCache()->get(body);
        assert(cfg);

        Replacer replacer(optimizer(), cfg, result);
        replacer.run(body);

        // Special case: propagate x = <something>; return <something>;
        propagateFunctionReturn(cfg, body);

        if ( replacer.isModified() )
            recordChange(body, "constant propagation");
    }

    void operator()(declaration::Function* n) override {
        const auto* body = n->function()->body();
        if ( ! body )
            return;

        PropagationMap init;
        for ( auto* param : n->function()->ftype()->parameters() )
            init[param].propagate = false;

        AnalysisResult result;
        populateDataflow(result, init, n);
        applyPropagation(n, result);
    }
};

bool run(Optimizer* optimizer) { return Mutator(optimizer).run(); }

optimizer::RegisterPass value_propagation(
    {.id = PassID::ValuePropagation, .iterate = true, .guarantees = Guarantees::None, .run = run});

} // namespace
