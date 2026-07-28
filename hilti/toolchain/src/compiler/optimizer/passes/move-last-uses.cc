// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/integer.h>
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

struct Collector : public optimizer::visitor::Collector {
    Collector(Optimizer* optimizer) : optimizer::visitor::Collector(optimizer) {}

    std::unordered_set<uint64_t> moveable; // All last-uses that are moveable

    void operator()(declaration::Function* n) override {
        const auto* body = n->function()->body();
        if ( ! body )
            return;

        AnalysisResult result;
        const auto* cfg = state()->cfgCache()->get(n->function()->body());
        assert(cfg);

        auto num_processed = _analyzeLiveness(result, cfg);
        HILTI_DEBUG(logging::debug::OptimizerPasses,
                    util::fmt("function %s took %d iterations before liveness converged", n->id(), num_processed));

        _applyLastUse(result, cfg);
    }

private:
    bool _transfer(const cfg::Transfer& dataflow, LivenessSet& current_in, const LivenessSet& current_out) {
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

    // Standard liveness analysis
    //
    // Returns the number of iterations it took to converge.
    int _analyzeLiveness(AnalysisResult& result, const CFG* cfg) {
        auto worklist = cfg->postorder();
        // Shadow set for existence checks.
        auto worklist_existence = std::unordered_set<cfg::GraphNode>(worklist.begin(), worklist.end());

        // We always expect the worklist to contain begin/end nodes
        assert(worklist.size() >= 1);
        auto num_processed = 0;

        while ( ! worklist.empty() ) {
            auto n = worklist.front();
            worklist.pop_front();
            worklist_existence.erase(n);

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
            const auto& node_dataflow = cfg->dataflow().at(n);
            if ( _transfer(node_dataflow, result.in[n], result.out[n]) ) {
                // Any changes to 'in' means predecessors need recalculated
                for ( auto pred_id : cfg->graph().neighborsUpstream(n->identity()) ) {
                    const auto* pred_node = cfg->graph().getNode(pred_id);

                    // Only add if it's not in there already
                    if ( worklist_existence.insert(*pred_node).second )
                        worklist.push_back(*pred_node);
                }
            }

            num_processed++;
        }

        return num_processed;
    }

    void _applyLastUse(const AnalysisResult& result, const CFG* cfg) {
        for ( const auto& [n, live_out] : result.out ) {
            auto* ast_node = n.get();
            assert(ast_node);
            const auto& node_dataflow = cfg->dataflow().at(n);

            for ( auto* candidate : node_dataflow.read ) {
                // All last uses that are not aliases
                if ( ! live_out.contains(candidate) && ! node_dataflow.maybe_alias.contains(candidate) )
                    _markMovableInNode(ast_node, candidate);
            }
        }
    }

    void _markMovableInNode(Node* n, Declaration* target) {
        if ( ! target->isA<declaration::LocalVariable>() )
            return;

        std::optional<uint64_t> opt_to_move = {};
        _walk(n, target, opt_to_move);

        if ( opt_to_move )
            moveable.insert(*opt_to_move);
    }

    // Walks args from a function or method call, skips anything we shouldn't move
    // from (inout, alias, etc).
    void _walkArgs(const node::Range<Expression> args,
                   type::Function* ft,
                   Declaration*& target,
                   std::optional<uint64_t>& to_move) {
        assert(args.size() == ft->parameters().size());

        // Do not walk any inout arguments or aliasing types.
        for ( const auto [i, operand] : util::enumerate(ft->parameters()) ) {
            if ( operand->kind() != hilti::parameter::Kind::InOut && ! operand->type()->type()->isAliasingType() )
                _walk(args[i], target, to_move);
        }
    }

    // Walks and marks the moveable IDs.
    //
    // An ID is generally only moveable if it's the only occurrence within a
    // node.
    void _walk(Node* n, Declaration*& target, std::optional<uint64_t>& to_move) {
        if ( ! n )
            return;

        if ( auto* move = n->tryAs<expression::Move>() ) {
            // If we already are moving this name, do not add any more moves
            if ( auto* name = move->expression()->tryAs<expression::Name>();
                 name && name->resolvedDeclaration() == target ) {
                to_move = {};
                target = nullptr;
                return;
            }

            return;
        }

        // If we saw this name and it matches the target, but we already are
        // moving this target, we cannot move. C++ has no guarantees about
        // expression ordering in cases like function calls.
        if ( auto* name = n->tryAs<expression::Name>(); name && to_move && name->resolvedDeclaration() == target ) {
            to_move = {};
            target = nullptr;
            return;
        }

        // LHS is forbidden, only walk source
        if ( auto* assign = n->tryAs<expression::Assign>() ) {
            _walk(assign->source(), target, to_move);
            return;
        }

        // For return value optimization - moves are unnecessary
        if ( n->isA<statement::Return>() || (n->isA<expression::Coerced>() && n->parent()->isA<statement::Return>()) )
            return;

        // Do not move the LHS of tuple assign
        if ( auto* custom = n->tryAs<operator_::tuple::CustomAssign>() ) {
            _walk(custom->op1(), target, to_move);

            return;
        }

        // Function and method calls should only mark their non-inout
        // arguments as movable. This gathers those facts and only
        // recurses on arguments which are potentially moveable.
        if ( auto* resolved = n->tryAs<operator_::struct_::MemberCall>() ) {
            const auto& op = static_cast<const struct_::MemberCall&>(resolved->operator_());
            auto* ft = op.declaration()->type()->type()->as<type::Function>();
            auto args = resolved->op2()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();

            _walk(resolved->op0(), target, to_move);
            _walkArgs(args, ft, target, to_move);
            return;
        }
        else if ( auto* resolved = n->tryAs<operator_::function::Call>() ) {
            auto* decl = context()->lookup(resolved->op0()->as<expression::Name>()->resolvedDeclarationIndex());
            auto* fdecl = decl->as<declaration::Function>();
            auto* ft = fdecl->function()->type()->type()->as<type::Function>();
            auto args = resolved->op1()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();

            _walkArgs(args, ft, target, to_move);
            return;
        }

        // If it's a name, check if it's the target. If so, mark it moveable.
        if ( const auto* name = n->tryAs<expression::Name>(); name && name->resolvedDeclaration() == target )
            to_move = n->identity();

        // Most nodes then just recurse their children
        for ( const auto& child : n->children() )
            _walk(child, target, to_move);
    }
};

// Just replaces all moveable nodes with a move node.
struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const std::unordered_set<uint64_t>& moveable)
        : optimizer::visitor::Mutator(optimizer), moveable(moveable) {}

    const std::unordered_set<uint64_t>& moveable;

    void operator()(expression::Name* n) override {
        if ( n->parent() && moveable.contains(n->identity()) )
            replaceNode(n, builder()->move(n), "marking movable");
    }
};

bool run(Optimizer* optimizer) {
    auto coll = Collector(optimizer);
    coll.run();

    return Mutator(optimizer, coll.moveable).run();
}

optimizer::RegisterPass move_last_uses({.id = PassID::MoveLastUses,
                                        .iterate = false,
                                        .guarantees = Guarantees::ConstantsFolded | Guarantees::Resolved,
                                        .run = run});

} // namespace
