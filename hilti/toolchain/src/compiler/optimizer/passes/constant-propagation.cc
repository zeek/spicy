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

struct ConstantValue {
    Expression* expr = nullptr;
    bool not_a_constant = false; // NAC

    bool operator==(const ConstantValue& other) const {
        // If both are NAC, what's in expr doesn't matter
        if ( not_a_constant && other.not_a_constant )
            return true;

        return expr == other.expr && not_a_constant == other.not_a_constant;
    }
};

using ConstantMap = std::map<Declaration*, ConstantValue>;

struct AnalysisResult {
    std::map<cfg::GraphNode, ConstantMap> in;
    std::map<cfg::GraphNode, ConstantMap> out;
};

// Marks all children that are names as not a constant in the given map.
// This is used by function calls, since they have deeply nested names
// that should all be marked NAC.
struct NameNACer : optimizer::visitor::Collector {
    NameNACer(Optimizer* optimizer, ConstantMap* constants)
        : optimizer::visitor::Collector(optimizer), constants(constants) {}

    ConstantMap* constants;

    void operator()(expression::Name* name) override {
        if ( auto* decl = name->resolvedDeclaration() )
            (*constants)[decl].not_a_constant = true;
    }
};

struct TransferVisitor : optimizer::visitor::Collector {
    TransferVisitor(Optimizer* optimizer, ConstantMap* constants)
        : optimizer::visitor::Collector(optimizer), constants(constants), name_nac(optimizer, constants) {}

    ConstantMap* constants;
    NameNACer name_nac;

    // Tries to evaluate an expression to a constant value given a map of known constants.
    Expression* evaluate(Expression* expr) {
        if ( expr->isConstant() && expr->isA<expression::Ctor>() )
            return expr;

        if ( const auto* name = expr->tryAs<expression::Name>() ) {
            if ( auto* decl = name->resolvedDeclaration(); decl && constants->contains(decl) ) {
                const auto& val = constants->at(decl);
                if ( val.not_a_constant )
                    return nullptr;

                return val.expr;
            }
        }

        return nullptr;
    }

    void operator()(expression::Assign* assign) override {
        if ( const auto* name = assign->target()->tryAs<expression::Name>() ) {
            if ( auto* decl = name->resolvedDeclaration() ) {
                auto* const_val = evaluate(assign->source());
                (*constants)[decl] = {.expr = const_val, .not_a_constant = (const_val == nullptr)};
            }
        }
    }

    void operator()(declaration::LocalVariable* decl) override {
        if ( auto* init = decl->init() ) {
            auto* const_val = evaluate(init);
            (*constants)[decl] = {.expr = const_val, .not_a_constant = (const_val == nullptr)};
        }
    }

    void operator()(operator_::struct_::MemberCall* op) override {
        // NAC anything used in a call; unfortunately they may silently
        // coerce to a reference.
        name_nac.run(op);
    }

    void operator()(operator_::function::Call* op) override {
        // NAC anything used in a call; unfortunately they may silently
        // coerce to a reference.
        name_nac.run(op);
    }

    void operator()(expression::ResolvedOperator* op) override {
        const auto& sig = op->operator_().signature();

        std::size_t i = 0;
        for ( const auto* operand : sig.operands->operands() ) {
            if ( operand->kind() == parameter::Kind::InOut )
                // NAC any names within
                name_nac.run(op->operands()[i]);

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

        const auto& constants = in_it->second;
        const auto& out_constants = out_it->second;
        auto const_it = constants.find(decl);
        auto out_const_it = out_constants.find(decl);
        if ( const_it == constants.end() || out_const_it == out_constants.end() )
            return;

        // If they aren't the same, something changed within the statement.
        // Since we're not sure which comes first, just abort.
        if ( const_it->second != out_const_it->second )
            return;

        auto const_val = const_it->second;

        if ( ! const_val.not_a_constant ) {
            Node* to_replace = n;
            // Replace the coercion, too, so that the coercer reruns.
            if ( auto* coerced = n->parent()->tryAs<expression::Coerced>() )
                to_replace = coerced;

            replaceNode(to_replace, const_val.expr, "propagating constant value");
        }
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer) : optimizer::visitor::Mutator(optimizer) {}

    std::map<Node*, AnalysisResult> analysis_results;

    void transfer(const cfg::GraphNode& n, ConstantMap& new_out) {
        TransferVisitor(optimizer(), &new_out).run(n.get());
    }

    void populateDataflow(AnalysisResult& result, const ConstantMap& init, const declaration::Function* function) {
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
            ConstantMap new_in;

            for ( auto pred : cfg->graph().neighborsUpstream(n->identity()) ) {
                const auto* cfg_node = cfg->graph().getNode(pred);

                // cfg_node was retrieved from the graph itself so should be present.
                assert(cfg_node);
                const auto& pred_out = result.out[*cfg_node];

                for ( const auto& [decl, const_val] : pred_out ) {
                    // Add if we can, otherwise NAC if they're not the same const.
                    auto [found, inserted] = new_in.try_emplace(decl, const_val);
                    if ( ! inserted && found->second != const_val )
                        found->second.not_a_constant = true;
                }
            }

            result.in[n] = std::move(new_in);

            // Transfer
            ConstantMap new_out = result.in[n];
            transfer(n, new_out);

            // If it changed, add successors to worklist
            ConstantMap old_out = result.out[n];

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

        ConstantMap init;
        for ( auto* param : n->function()->ftype()->parameters() )
            init[param].not_a_constant = true;

        AnalysisResult result;
        populateDataflow(result, init, n);
        applyPropagation(n, result);
    }
};

bool run(Optimizer* optimizer) { return Mutator(optimizer).run(); }

optimizer::RegisterPass constant_propagation(
    {.id = PassID::ConstantPropagation, .iterate = true, .guarantees = Guarantees::None, .run = run});

} // namespace
