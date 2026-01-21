#include <algorithm>

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/cfg.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

using LivenessSet = std::set<Declaration*>;

struct AnalysisResult {
    std::map<cfg::GraphNode, LivenessSet> in;
    std::map<cfg::GraphNode, LivenessSet> out;
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer) : optimizer::visitor::Mutator(optimizer) {}

    std::map<Node*, AnalysisResult> analysis_results;

    bool transfer(const cfg::GraphNode& n, const cfg::Transfer& dataflow, LivenessSet& current_in,
                  const LivenessSet& current_out) {
        auto old_in = current_in;

        LivenessSet new_in = current_out;

        for ( const auto& wrote : dataflow.write )
            new_in.erase(wrote);

        for ( const auto& read : dataflow.read )
            new_in.insert(read);

        if ( new_in != old_in ) {
            current_in = std::move(new_in);
            return true;
        }

        return false;
    }

    void populateDataflow(AnalysisResult& result, const declaration::Function* function) {
        const auto* cfg = state()->cfgCache()->get(function->function()->body());
        assert(cfg);

        auto worklist = cfg->postorder();

        // We always expect the worklist to contain begin/end nodes
        assert(worklist.size() >= 1);
        auto num_processed = 0;

        while ( ! worklist.empty() ) {
            auto n = worklist.front();
            worklist.pop_front();

            // Meet: out is the union of in of all successors
            LivenessSet new_out;
            for ( auto succ_id : cfg->graph().neighborsDownstream(n->identity()) ) {
                const auto* succ_node = cfg->graph().getNode(succ_id);
                assert(succ_node);

                const auto& succ_in = result.in[*succ_node];
                new_out.insert(succ_in.begin(), succ_in.end());
            }
            result.out[n] = new_out;

            // Transfer
            // TODO: Do something with alias in the transfer? maybe elsewhere?
            const auto& node_dataflow = cfg->dataflow().at(n);
            if ( transfer(n, node_dataflow, result.in[n], result.out[n]) ) {
                // Any changes to 'in' means predecessors need recalculated
                for ( auto pred_id : cfg->graph().neighborsUpstream(n->identity()) ) {
                    const auto* pred_node = cfg->graph().getNode(pred_id);

                    // Only add if it's not in there already
                    if ( std::ranges::find(worklist, *pred_node) == worklist.end() )
                        worklist.push_back(*pred_node);
                }
            }

            num_processed++;
        }

        HILTI_DEBUG(logging::debug::OptimizerPasses,
                    util::fmt("function %s took %d iterations before liveness converged", function->id(),
                              num_processed));
    }

    void applyLastUse(const AnalysisResult& result, const declaration::Function* function) {
        auto* body = function->function()->body();
        const auto* cfg = state()->cfgCache()->get(body);
        assert(cfg);

        for ( const auto& [n, live_out] : result.out ) {
            auto* ast_node = n.get();
            assert(ast_node);
            const auto& node_dataflow = cfg->dataflow().at(n);

            for ( auto* candidate : node_dataflow.read ) {
                if ( ! live_out.contains(candidate) )
                    markMovableInNode(ast_node, candidate);
            }
        }
    }

    void markMovableInNode(Node* root, Declaration* target) {
        // TODO: This is an inner visitor because it makes it easier to apply
        // the dataflow facts, but should probably change it.
        struct Mover : optimizer::visitor::Mutator {
            Declaration* target;
            bool done = false;

            Mover(Optimizer* opt, Declaration* t) : optimizer::visitor::Mutator(opt), target(t) {}

            // Ensures this is a valid move. That means that it's not on the
            // LHS, it's not a global, etc.
            bool isValid(Expression* expr) {
                // TODO don't move if in move or return? And remove the move
                // check from operator()
                auto* parent = expr->parent();

                if ( expr->type()->type()->isA<type::Function>() )
                    return false;

                if ( auto* a = parent->tryAs<expression::Assign>() )
                    return a->target() != expr;

                // For return value optimization
                if ( parent->isA<statement::Return>() ||
                     (parent->isA<expression::Coerced>() && expr->parent(2)->isA<statement::Return>()) )
                    return false;

                // Would cause infinite loop
                if ( parent->isA<expression::Move>() )
                    return false;

                // LHS of tuple assign
                if ( auto* custom = parent->tryAs<operator_::tuple::CustomAssign>() )
                    if ( custom->op0() == expr )
                        return false;

                // TODO: inout params?

                return true;
            }

            // TODO: What if it's used multiple times?
            void operator()(expression::Name* n) override {
                if ( ! done && n->resolvedDeclaration() == target && isValid(n) )
                    replaceNode(n, builder()->move(n), "marking movable");
            }
        };

        if ( ! target->isA<declaration::LocalVariable>() )
            return;

        Mover mover(optimizer(), target);
        mover.run(root);
        if ( mover.isModified() )
            setModified();
    }

    void operator()(declaration::Function* n) override {
        const auto* body = n->function()->body();
        if ( ! body )
            return;

        AnalysisResult result;
        populateDataflow(result, n);
        applyLastUse(result, n);
    }
};

bool run(Optimizer* optimizer) { return Mutator(optimizer).run(); }

optimizer::RegisterPass move_ids(
    // TODO
    {.id = PassID::MoveIDs, .iterate = false, .guarantees = Guarantees::None, .run = run});

} // namespace
